use async_trait::async_trait;
use bytes::BytesMut;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::io::ErrorKind;
use std::io::ErrorKind::Other;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::time::Duration;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{client::TlsStream, rustls, TlsConnector};

use crate::{encode::ToByte, error::Result};

use super::{load_certs, load_keys, BrokerAddress, BrokerConnection};

#[derive(Clone, Debug)]
pub struct TlsConnection {
    stream: Arc<Mutex<TlsStream<TcpStream>>>,
}

/// TLS connection options.
#[derive(Clone, Debug)]
pub struct TlsConnectionOptions {
    pub broker_options: Vec<BrokerAddress>,
    pub key: PathBuf,
    pub cert: PathBuf,
    pub cafile: Option<PathBuf>,
}

impl TlsConnection {
    pub async fn new_(options: TlsConnectionOptions) -> Result<Self> {
        tracing::debug!(
            "Starting connection to {} brokers",
            options.broker_options.len()
        );
        let mut propagated_err: Option<crate::error::Error> = None;

        let mut root_cert_store = rustls::RootCertStore::empty();
        if let Some(cafile) = &options.cafile {
            let mut pem = BufReader::new(File::open(cafile).unwrap());
            for cert in rustls_pemfile::certs(&mut pem) {
                root_cert_store.add(cert.unwrap()).unwrap();
            }
        } else {
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        for broker_option in options.broker_options.iter() {
            let addr = (broker_option.host.as_str(), broker_option.port)
                .to_socket_addrs()
                .map_err(|_| crate::error::Error::IoError(ErrorKind::NotFound))?
                .next()
                .ok_or_else(|| crate::error::Error::IoError(ErrorKind::NotFound))?;

            tracing::debug!("Connecting to {}", broker_option.host);
            let certs =
                load_certs(&options.cert).map_err(|e| crate::error::Error::IoError(e.kind()))?;
            let key =
                load_keys(&options.key).map_err(|e| crate::error::Error::IoError(e.kind()))?;

            let connection_result = tokio::time::timeout(Duration::from_secs(10), async {
                let tcp_stream = TcpStream::connect(addr)
                    .await
                    .map_err(|e| crate::error::Error::IoError(e.kind()))?;

                tracing::debug!("connected on tcp");

                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(root_cert_store.clone())
                    .with_client_auth_cert(certs, key)
                    .unwrap();

                let connector = TlsConnector::from(Arc::new(config));
                let domain = rustls_pki_types::ServerName::try_from(broker_option.host.clone())
                    .map_err(|_| crate::error::Error::IoError(ErrorKind::InvalidInput))?
                    .to_owned();

                let stream = connector.connect(domain, tcp_stream).await.map_err(|e| {
                    if let Some(err) = e.source() {
                        log::error!("failed to connect to broker over TLS: {:?}", err);
                    } else {
                        log::error!("failed to connect to broker over TLS: {}", e);
                    }
                    crate::error::Error::IoError(Other)
                })?;

                Ok::<TlsStream<TcpStream>, crate::error::Error>(stream)
            })
            .await;

            match connection_result {
                Ok(Ok(stream)) => {
                    tracing::debug!("tls connected to tcp");
                    return Ok(Self {
                        stream: Arc::new(Mutex::new(stream)),
                    });
                }
                Ok(Err(e)) => {
                    propagated_err = Some(e);
                }
                Err(_) => {
                    tracing::debug!("Connection timeout for broker {}", broker_option.host);
                    propagated_err = Some(crate::error::Error::IoError(ErrorKind::TimedOut));
                }
            }
        }

        if let Some(e) = propagated_err {
            return Err(e);
        }

        Err(crate::error::Error::IoError(ErrorKind::NotFound))
    }

    pub async fn send_request_<R: ToByte + Send>(&mut self, req: &R) -> Result<()> {
        let mut buffer = Vec::with_capacity(4);

        buffer.extend_from_slice(&[0, 0, 0, 0]);
        req.encode(&mut buffer)?;

        let size = buffer.len() as i32 - 4;
        size.encode(&mut &mut buffer[..])?;

        tracing::trace!("Sending bytes {}", buffer.len());

        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = self.stream.lock().await;
            stream
                .write_all(&buffer)
                .await
                .map_err(|e| crate::error::Error::IoError(e.kind()))?;
            stream
                .flush()
                .await
                .map_err(|e| crate::error::Error::IoError(e.kind()))?;
            Ok::<(), crate::error::Error>(())
        })
        .await
        .map_err(|_| crate::error::Error::IoError(ErrorKind::TimedOut))?
    }

    pub async fn receive_response_(&mut self) -> Result<BytesMut> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = self.stream.lock().await;

            let length = stream
                .read_u32()
                .await
                .map_err(|e| crate::error::Error::IoError(e.kind()))?;

            tracing::trace!("Reading {} bytes", length);
            let mut buffer = BytesMut::zeroed(length as usize);

            stream
                .read_exact(&mut buffer)
                .await
                .map_err(|e| crate::error::Error::IoError(e.kind()))?;
            tracing::trace!("Read {:?}", buffer);

            Ok::<BytesMut, crate::error::Error>(buffer)
        })
        .await
        .map_err(|_| crate::error::Error::IoError(ErrorKind::TimedOut))?
    }
}

#[async_trait]
impl BrokerConnection for TlsConnection {
    type ConnConfig = TlsConnectionOptions;

    async fn send_request<R: ToByte + Sync + Send>(&mut self, req: &R) -> Result<()> {
        self.send_request_(req).await
    }

    async fn receive_response(&mut self) -> Result<BytesMut> {
        self.receive_response_().await
    }

    async fn new(p: Self::ConnConfig) -> Result<Self> {
        Self::new_(p).await
    }

    async fn from_addr(options: Self::ConnConfig, addr: BrokerAddress) -> Result<Self> {
        let cafile = options.cafile.clone();

        let options = TlsConnectionOptions {
            broker_options: vec![addr],
            cert: options.cert,
            key: options.key,
            cafile,
        };

        Self::new_(options).await
    }
}