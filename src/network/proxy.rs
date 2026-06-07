use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::BytesMut;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::io::ErrorKind;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::time::Duration;
use std::{io, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{client::TlsStream, rustls, TlsConnector};

use crate::{
    encode::ToByte,
    error::{Error, Result},
};

use super::sasl::{do_sasl_v2, SaslConfig};
use super::{BrokerAddress, BrokerConnection};

/// HTTP proxy configuration
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// TLS configuration for proxy connections
#[derive(Clone, Debug)]
pub struct ProxyTlsConfig {
    pub key: PathBuf,
    pub cert: PathBuf,
    pub cafile: Option<PathBuf>,
}

/// Plain TCP connection through HTTP CONNECT proxy.
#[derive(Clone, Debug)]
pub struct ProxyTcpConnection {
    stream: Arc<Mutex<TcpStream>>,
}

/// TCP connection options with proxy support
#[derive(Clone, Debug)]
pub struct ProxyTcpConfig {
    pub broker_options: Vec<BrokerAddress>,
    pub proxy: ProxyConfig,
}

impl ProxyTcpConnection {
    /// Connect to a Kafka/Redpanda broker through HTTP proxy
    pub async fn new_(config: ProxyTcpConfig) -> Result<Self> {
        let mut propagated_err: Option<Error> = None;

        for broker_addr in config.broker_options.iter() {
            tracing::debug!(
                "Connecting to {} through proxy {}:{}",
                broker_addr.host,
                config.proxy.host,
                config.proxy.port
            );

            match connect_through_proxy(&config.proxy, broker_addr).await {
                Ok(stream) => {
                    tracing::debug!("successfully connected through proxy");
                    return Ok(Self {
                        stream: Arc::new(Mutex::new(stream)),
                    });
                }
                Err(e) => {
                    propagated_err = Some(e);
                }
            }
        }

        Err(propagated_err.unwrap_or(Error::IoError(ErrorKind::NotFound)))
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
                .map_err(|e| Error::IoError(e.kind()))?;
            stream.flush().await.map_err(|e| Error::IoError(e.kind()))?;
            Ok::<(), Error>(())
        })
        .await
        .map_err(|_| Error::IoError(ErrorKind::TimedOut))?
    }

    pub async fn receive_response_(&mut self) -> Result<BytesMut> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = self.stream.lock().await;

            let length = stream
                .read_u32()
                .await
                .map_err(|e| Error::IoError(e.kind()))?;

            tracing::trace!("Reading {} bytes", length);
            let mut buffer = BytesMut::zeroed(length as usize);

            stream
                .read_exact(&mut buffer)
                .await
                .map_err(|e| Error::IoError(e.kind()))?;

            Ok::<BytesMut, Error>(buffer)
        })
        .await
        .map_err(|_| Error::IoError(ErrorKind::TimedOut))?
    }
}

#[async_trait]
impl BrokerConnection for ProxyTcpConnection {
    type ConnConfig = ProxyTcpConfig;

    async fn send_request<R: ToByte + Sync + Send>(&mut self, req: &R) -> Result<()> {
        self.send_request_(req).await
    }

    async fn receive_response(&mut self) -> Result<BytesMut> {
        self.receive_response_().await
    }

    async fn new(p: Self::ConnConfig) -> Result<Self> {
        Self::new_(p).await
    }

    async fn from_addr(config: Self::ConnConfig, addr: BrokerAddress) -> Result<Self> {
        Self::new_(ProxyTcpConfig {
            broker_options: vec![addr],
            proxy: config.proxy,
        })
        .await
    }
}

/// TLS connection through HTTP CONNECT proxy.
#[derive(Clone, Debug)]
pub struct ProxyTlsConnection {
    stream: Arc<Mutex<TlsStream<TcpStream>>>,
}

/// TLS connection options with proxy support
#[derive(Clone, Debug)]
pub struct ProxyTlsConnectionOptions {
    pub broker_options: Vec<BrokerAddress>,
    pub proxy: ProxyConfig,
    pub tls_config: ProxyTlsConfig,
}

impl ProxyTlsConnection {
    pub async fn new_(options: ProxyTlsConnectionOptions) -> Result<Self> {
        let mut propagated_err: Option<Error> = None;

        let mut root_cert_store = rustls::RootCertStore::empty();
        if let Some(cafile) = &options.tls_config.cafile {
            let mut pem = BufReader::new(File::open(cafile).map_err(|e| Error::IoError(e.kind()))?);
            for cert in rustls_pemfile::certs(&mut pem) {
                root_cert_store
                    .add(cert.map_err(|_| Error::IoError(ErrorKind::InvalidData))?)
                    .map_err(|_| Error::IoError(ErrorKind::InvalidData))?;
            }
        } else {
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        for broker_option in options.broker_options.iter() {
            let certs =
                load_certs(&options.tls_config.cert).map_err(|e| Error::IoError(e.kind()))?;
            let key = load_keys(&options.tls_config.key).map_err(|e| Error::IoError(e.kind()))?;

            let connection_result = tokio::time::timeout(Duration::from_secs(30), async {
                // Establish TCP tunnel through proxy
                let tcp_stream = connect_through_proxy(&options.proxy, broker_option).await?;

                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(root_cert_store.clone())
                    .with_client_auth_cert(certs, key)
                    .map_err(|_| Error::IoError(ErrorKind::InvalidData))?;

                let connector = TlsConnector::from(Arc::new(config));
                let domain = rustls_pki_types::ServerName::try_from(broker_option.host.clone())
                    .map_err(|_| Error::IoError(ErrorKind::InvalidInput))?
                    .to_owned();

                let tls_stream = connector
                    .connect(domain, tcp_stream)
                    .await
                    .map_err(|e| Error::IoError(e.kind()))?;

                Ok::<TlsStream<TcpStream>, Error>(tls_stream)
            })
            .await;

            match connection_result {
                Ok(Ok(tls_stream)) => {
                    return Ok(Self {
                        stream: Arc::new(Mutex::new(tls_stream)),
                    });
                }
                Ok(Err(e)) => {
                    propagated_err = Some(e);
                }
                Err(_) => {
                    tracing::debug!("connection timeout for broker {}", broker_option.host);
                    propagated_err = Some(Error::IoError(ErrorKind::TimedOut));
                }
            }
        }

        Err(propagated_err.unwrap_or(Error::IoError(ErrorKind::NotFound)))
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
                .map_err(|e| Error::IoError(e.kind()))?;
            stream.flush().await.map_err(|e| Error::IoError(e.kind()))?;
            Ok::<(), Error>(())
        })
        .await
        .map_err(|_| Error::IoError(ErrorKind::TimedOut))?
    }

    pub async fn receive_response_(&mut self) -> Result<BytesMut> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = self.stream.lock().await;

            let length = stream
                .read_u32()
                .await
                .map_err(|e| Error::IoError(e.kind()))?;

            tracing::trace!("Reading {} bytes", length);
            let mut buffer = BytesMut::zeroed(length as usize);

            stream
                .read_exact(&mut buffer)
                .await
                .map_err(|e| Error::IoError(e.kind()))?;

            Ok::<BytesMut, Error>(buffer)
        })
        .await
        .map_err(|_| Error::IoError(ErrorKind::TimedOut))?
    }
}

#[async_trait]
impl BrokerConnection for ProxyTlsConnection {
    type ConnConfig = ProxyTlsConnectionOptions;

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
        Self::new_(ProxyTlsConnectionOptions {
            broker_options: vec![addr],
            proxy: options.proxy,
            tls_config: options.tls_config,
        })
        .await
    }
}

/// Shared HTTP CONNECT tunnel logic used by both TCP and TLS proxy connections.
async fn connect_through_proxy(proxy: &ProxyConfig, target: &BrokerAddress) -> Result<TcpStream> {
    let proxy_addr = (proxy.host.as_str(), proxy.port)
        .to_socket_addrs()
        .map_err(|_| Error::IoError(ErrorKind::InvalidInput))?
        .next()
        .ok_or(Error::IoError(ErrorKind::NotFound))?;

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|e| Error::IoError(e.kind()))?;

    tracing::debug!("connected to proxy at {}:{}", proxy.host, proxy.port);

    // Build and send HTTP CONNECT request
    let auth_header = match (&proxy.username, &proxy.password) {
        (Some(user), Some(pass)) => {
            let creds = BASE64.encode(format!("{}:{}", user, pass));
            format!("Proxy-Authorization: Basic {}\r\n", creds)
        }
        (Some(user), None) => {
            let creds = BASE64.encode(format!("{}:", user));
            format!("Proxy-Authorization: Basic {}\r\n", creds)
        }
        _ => String::new(),
    };

    let connect_req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}Connection: keep-alive\r\n\r\n",
        host = target.host,
        port = target.port,
        auth = auth_header,
    );

    stream
        .write_all(connect_req.as_bytes())
        .await
        .map_err(|e| Error::IoError(e.kind()))?;
    stream.flush().await.map_err(|e| Error::IoError(e.kind()))?;

    // Read byte-by-byte until \r\n\r\n — same approach as before but using
    // proper async read_exact rather than try_read busy-wait
    let mut header_buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut byte))
            .await
            .map_err(|_| Error::IoError(ErrorKind::TimedOut))?
            .map_err(|e| Error::IoError(e.kind()))?;

        header_buf.push(byte[0]);

        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buf.len() > 8192 {
            return Err(Error::IoError(ErrorKind::InvalidData));
        }
    }

    let response_str = std::str::from_utf8(&header_buf).unwrap_or("<non-utf8 proxy response>");
    tracing::debug!(
        "proxy response: {}",
        response_str.lines().next().unwrap_or("")
    );

    if !header_buf.starts_with(b"HTTP/1.") || !response_str.contains(" 200 ") {
        tracing::error!(
            "proxy CONNECT rejected: {}",
            response_str.lines().next().unwrap_or("(empty)")
        );
        return Err(Error::IoError(ErrorKind::PermissionDenied));
    }

    tracing::debug!(
        "proxy tunnel established to {}:{}",
        target.host,
        target.port
    );
    Ok(stream)
}

// SASL variants — unchanged structurally, just wired to the fixed connection types above

#[derive(Clone, Debug)]
pub struct SaslProxyTcpConfig {
    pub proxy_config: ProxyTcpConfig,
    pub sasl_config: SaslConfig,
}

#[derive(Clone, Debug)]
pub struct SaslProxyTcpConnection {
    conn: ProxyTcpConnection,
}

#[async_trait]
impl BrokerConnection for SaslProxyTcpConnection {
    type ConnConfig = SaslProxyTcpConfig;

    async fn send_request<R: ToByte + Sync + Send>(&mut self, req: &R) -> Result<()> {
        self.conn.send_request_(req).await
    }

    async fn receive_response(&mut self) -> Result<BytesMut> {
        self.conn.receive_response_().await
    }

    async fn new(p: Self::ConnConfig) -> Result<Self> {
        let conn = do_sasl_v2(
            async || ProxyTcpConnection::new_(p.proxy_config.clone()).await,
            p.sasl_config.correlation_id,
            &p.sasl_config.client_id,
            p.sasl_config.clone(),
        )
        .await?;
        Ok(Self { conn })
    }

    async fn from_addr(p: Self::ConnConfig, addr: BrokerAddress) -> Result<Self> {
        Self::new(SaslProxyTcpConfig {
            proxy_config: ProxyTcpConfig {
                broker_options: vec![addr],
                proxy: p.proxy_config.proxy,
            },
            sasl_config: p.sasl_config,
        })
        .await
    }
}

/// SASL TLS connection through proxy
#[derive(Clone, Debug)]
pub struct SaslProxyTlsConfig {
    pub proxy_tls_config: ProxyTlsConnectionOptions,
    pub sasl_config: SaslConfig,
}

#[derive(Clone, Debug)]
pub struct SaslProxyTlsConnection {
    conn: ProxyTlsConnection,
}

#[async_trait]
impl BrokerConnection for SaslProxyTlsConnection {
    type ConnConfig = SaslProxyTlsConfig;

    async fn send_request<R: ToByte + Sync + Send>(&mut self, req: &R) -> Result<()> {
        self.conn.send_request_(req).await
    }

    async fn receive_response(&mut self) -> Result<BytesMut> {
        self.conn.receive_response_().await
    }

    async fn new(p: Self::ConnConfig) -> Result<Self> {
        let conn = do_sasl_v2(
            async || ProxyTlsConnection::new_(p.proxy_tls_config.clone()).await,
            p.sasl_config.correlation_id,
            &p.sasl_config.client_id,
            p.sasl_config.clone(),
        )
        .await?;
        Ok(Self { conn })
    }

    async fn from_addr(p: Self::ConnConfig, addr: BrokerAddress) -> Result<Self> {
        Self::new(SaslProxyTlsConfig {
            proxy_tls_config: ProxyTlsConnectionOptions {
                broker_options: vec![addr],
                proxy: p.proxy_tls_config.proxy,
                tls_config: p.proxy_tls_config.tls_config,
            },
            sasl_config: p.sasl_config,
        })
        .await
    }
}

fn load_certs(path: &std::path::Path) -> io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

fn load_keys(path: &std::path::Path) -> io::Result<PrivateKeyDer<'static>> {
    match rsa_private_keys(&mut BufReader::new(File::open(path)?)).next() {
        Some(Ok(key)) => Ok(key.into()),
        Some(Err(e)) => Err(e),
        None => pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
            .next()
            .unwrap()
            .map(Into::into),
    }
}
