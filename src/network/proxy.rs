use std::fs::File;
use std::io::BufReader;
use std::io::ErrorKind;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::{io, sync::Arc};

use async_trait::async_trait;
use bytes::BytesMut;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
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

/// Plain TCP connection through HTTP proxy
#[derive(Clone, Debug)]
pub struct ProxyTcpConnection {
    stream: Arc<TcpStream>,
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

            match Self::connect_through_proxy(&config.proxy, broker_addr).await {
                Ok(stream) => {
                    tracing::debug!("Successfully connected through proxy");
                    return Ok(Self {
                        stream: Arc::new(stream),
                    });
                }
                Err(e) => {
                    propagated_err = Some(e);
                }
            }
        }

        if let Some(e) = propagated_err {
            return Err(e);
        }

        Err(Error::IoError(ErrorKind::NotFound))
    }

    async fn connect_through_proxy(
        proxy: &ProxyConfig,
        target: &BrokerAddress,
    ) -> Result<TcpStream> {
        // Connect to the proxy server
        let proxy_addr = (proxy.host.as_str(), proxy.port)
            .to_socket_addrs()
            .map_err(|_| Error::IoError(ErrorKind::InvalidInput))?
            .next()
            .ok_or_else(|| Error::IoError(ErrorKind::NotFound))?;

        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .map_err(|e| Error::IoError(e.kind()))?;

        tracing::debug!("Connected to proxy at {}:{}", proxy.host, proxy.port);

        // Send CONNECT request
        let connect_request = Self::build_connect_request(proxy, target);
        stream
            .write_all(connect_request.as_bytes())
            .await
            .map_err(|e| Error::IoError(e.kind()))?;
        stream.flush().await.map_err(|e| Error::IoError(e.kind()))?;

        tracing::debug!("Sent CONNECT request to proxy");

        // Read response byte by byte until we get the full HTTP response
        let mut response_buffer = Vec::new();
        let mut headers_complete = false;

        // Read until we find \r\n\r\n (end of HTTP headers)
        while !headers_complete {
            let mut byte = [0u8; 1];
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                stream.read_exact(&mut byte),
            )
            .await
            {
                Ok(Ok(_)) => {
                    response_buffer.push(byte[0]);

                    // Check for \r\n\r\n sequence
                    if response_buffer.len() >= 4 {
                        let len = response_buffer.len();
                        if &response_buffer[len - 4..len] == b"\r\n\r\n" {
                            headers_complete = true;
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::error!("Error reading from proxy: {:?}", e);
                    return Err(Error::IoError(e.kind()));
                }
                Err(_) => {
                    tracing::error!("Timeout reading proxy response");
                    return Err(Error::IoError(ErrorKind::TimedOut));
                }
            }
        }

        let response_str = String::from_utf8_lossy(&response_buffer);
        tracing::debug!("Full proxy response:\n{}", response_str);

        // Parse the status line
        let lines: Vec<&str> = response_str.lines().collect();
        if lines.is_empty() {
            tracing::error!("Empty response from proxy");
            return Err(Error::IoError(ErrorKind::InvalidData));
        }

        let status_line = lines[0];
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            tracing::error!("Invalid HTTP status line: {}", status_line);
            return Err(Error::IoError(ErrorKind::InvalidData));
        }

        let status_code = parts[1];
        if status_code != "200" {
            tracing::error!("Proxy CONNECT failed with status: {}", status_code);
            // Log all response lines for debugging
            for line in lines {
                tracing::error!("Proxy response line: {}", line);
            }
            return Err(Error::IoError(ErrorKind::PermissionDenied));
        }

        tracing::debug!(
            "Proxy tunnel established to {}:{}",
            target.host,
            target.port
        );
        Ok(stream)
    }

    fn build_connect_request(proxy: &ProxyConfig, target: &BrokerAddress) -> String {
        let mut request = format!(
            "CONNECT {}:{} HTTP/1.1\r\n\
             Host: {}:{}\r\n",
            target.host, target.port, target.host, target.port
        );

        // Add proxy authentication if credentials are provided
        if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
            let credentials = format!("{}:{}", username, password);
            let encoded = base64::encode(credentials);
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }

        request.push_str("\r\n"); // End of headers
        request
    }

    async fn read(&mut self, size: usize) -> Result<BytesMut> {
        let mut buf = BytesMut::zeroed(size);
        let mut index = 0_usize;
        loop {
            self.stream
                .readable()
                .await
                .map_err(|e| Error::IoError(e.kind()))?;

            match self.stream.try_read(&mut buf[index..]) {
                Ok(0) => {
                    tracing::info!("Empty read: connection was closed by server");
                    return Err(Error::MissingData("Connection closed".to_owned()));
                }
                Ok(n) => {
                    index += n;
                    tracing::trace!("Read {} bytes", n);
                    if index != size {
                        tracing::trace!("Going back to read more, {} bytes left", size - index);
                    } else {
                        return Ok(buf);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    tracing::trace!("WouldBlock on read");
                    continue;
                }
                Err(e) => {
                    tracing::error!("ERROR: Reading on Socket {:?}", e);
                    return Err(Error::IoError(e.kind()));
                }
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let size = buf.len();
        let mut index = 0_usize;
        loop {
            self.stream
                .writable()
                .await
                .map_err(|e| Error::IoError(e.kind()))?;

            match self.stream.try_write(&buf[index..]) {
                Ok(n) => {
                    index += n;
                    tracing::trace!("Wrote {} bytes", n);
                    if index != size {
                        tracing::trace!("Going back to write more, {} bytes left", size - index);
                    } else {
                        return Ok(n);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    tracing::trace!("WouldBlock on write");
                    continue;
                }
                Err(e) => {
                    tracing::error!("ERROR: Writing to Socket {:?}", e);
                    return Err(Error::IoError(e.kind()));
                }
            }
        }
    }

    pub async fn send_request_<R: ToByte + Send>(&mut self, req: &R) -> Result<()> {
        let mut buffer = Vec::with_capacity(4);
        buffer.extend_from_slice(&[0, 0, 0, 0]);
        req.encode(&mut buffer)?;

        let size = buffer.len() as i32 - 4;
        size.encode(&mut &mut buffer[..])?;

        tracing::trace!("Sending bytes {}", buffer.len());
        self.write(&buffer).await?;
        Ok(())
    }

    pub async fn receive_response_(&mut self) -> Result<BytesMut> {
        use bytes::Buf;
        let mut size = self.read(4).await?;
        let length = size.get_u32();
        tracing::trace!("Reading {} bytes", length);
        self.read(length as usize).await
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
        let proxy_config = ProxyTcpConfig {
            broker_options: vec![addr],
            proxy: config.proxy,
        };
        Self::new_(proxy_config).await
    }
}

/// TLS connection through HTTP proxy
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
        println!("ProxyTlsConnection::new_() called");
        let mut propagated_err: Option<Error> = None;

        // Set up root certificates
        let mut root_cert_store = rustls::RootCertStore::empty();
        if let Some(cafile) = &options.tls_config.cafile {
            println!("Loading custom CA file: {:?}", cafile);
            let mut pem = BufReader::new(File::open(cafile).map_err(|e| Error::IoError(e.kind()))?);
            for cert in rustls_pemfile::certs(&mut pem) {
                root_cert_store
                    .add(cert.map_err(|_| Error::IoError(ErrorKind::InvalidData))?)
                    .map_err(|_| Error::IoError(ErrorKind::InvalidData))?;
            }
        } else {
            println!("Using system CA store");
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        for broker_option in options.broker_options.iter() {
            println!("Attempting to connect to broker: {}", broker_option.host);

            let certs = load_certs(&options.tls_config.cert).map_err(|e| {
                println!("Failed to load certs: {:?}", e);
                Error::IoError(e.kind())
            })?;
            let key = load_keys(&options.tls_config.key).map_err(|e| {
                println!("Failed to load key: {:?}", e);
                Error::IoError(e.kind())
            })?;

            println!("Certs and keys loaded successfully");

            // Establish TCP connection through proxy
            println!("About to call connect_through_proxy");
            let tcp_stream = match ProxyTcpConnection::connect_through_proxy(
                &options.proxy,
                broker_option,
            )
            .await
            {
                Ok(stream) => {
                    println!("Proxy connection successful!");
                    stream
                }
                Err(e) => {
                    println!("Proxy connection failed: {:?}", e);
                    propagated_err = Some(e);
                    continue;
                }
            };

            println!("Setting up TLS configuration");

            // Set up TLS with proper ServerName
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_cert_store.clone())
                .with_client_auth_cert(certs, key)
                .map_err(|e| {
                    println!("Failed to create TLS config: {:?}", e);
                    Error::IoError(ErrorKind::InvalidData)
                })?;

            let connector = TlsConnector::from(Arc::new(config));

            // Use the broker hostname for TLS SNI, not the proxy hostname
            let domain = rustls_pki_types::ServerName::try_from(broker_option.host.clone())
                .map_err(|_| Error::IoError(ErrorKind::InvalidInput))?
                .to_owned();

            println!(
                "Starting TLS handshake with ServerName: {}",
                broker_option.host
            );

            match connector.connect(domain, tcp_stream).await {
                Ok(tls_stream) => {
                    println!("TLS connection established through proxy");
                    return Ok(Self {
                        stream: Arc::new(Mutex::new(tls_stream)),
                    });
                }
                Err(e) => {
                    println!("TLS handshake failed: {:?}", e);
                    propagated_err = Some(Error::IoError(e.kind()));
                }
            }
        }

        if let Some(e) = propagated_err {
            println!("All connections failed, returning error: {:?}", e);
            return Err(e);
        }

        println!("No brokers to connect to");
        Err(Error::IoError(ErrorKind::NotFound))
    }

    pub async fn send_request_<R: ToByte + Send>(&mut self, req: &R) -> Result<()> {
        let mut buffer = Vec::with_capacity(4);
        buffer.extend_from_slice(&[0, 0, 0, 0]);
        req.encode(&mut buffer)?;

        let size = buffer.len() as i32 - 4;
        size.encode(&mut &mut buffer[..])?;

        tracing::trace!("Sending bytes {}", buffer.len());
        let mut stream = self.stream.lock().await;
        stream
            .write_all(&buffer)
            .await
            .map_err(|e| Error::IoError(e.kind()))?;
        stream.flush().await.map_err(|e| Error::IoError(e.kind()))?;

        Ok(())
    }

    pub async fn receive_response_(&mut self) -> Result<BytesMut> {
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

        Ok(buffer)
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
        let proxy_options = ProxyTlsConnectionOptions {
            broker_options: vec![addr],
            proxy: options.proxy,
            tls_config: options.tls_config,
        };
        Self::new_(proxy_options).await
    }
}

/// SASL TCP connection through proxy
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
        let config = SaslProxyTcpConfig {
            proxy_config: ProxyTcpConfig {
                broker_options: vec![addr],
                proxy: p.proxy_config.proxy,
            },
            sasl_config: p.sasl_config,
        };
        Self::new(config).await
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
        let config = SaslProxyTlsConfig {
            proxy_tls_config: ProxyTlsConnectionOptions {
                broker_options: vec![addr],
                proxy: p.proxy_tls_config.proxy,
                tls_config: p.proxy_tls_config.tls_config,
            },
            sasl_config: p.sasl_config,
        };
        Self::new(config).await
    }
}

// Helper functions
fn load_certs(path: &std::path::Path) -> io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

fn load_keys(path: &std::path::Path) -> io::Result<PrivateKeyDer<'static>> {
    match rsa_private_keys(&mut BufReader::new(File::open(path)?)).next() {
        Some(Ok(rsa_private_key)) => Ok(rsa_private_key.into()),
        Some(Err(e)) => Err(e),
        None => pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
            .next()
            .unwrap()
            .map(Into::into),
    }
}
