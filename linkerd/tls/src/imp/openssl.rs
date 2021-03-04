use linkerd_identity::{ClientConfig, Name, ServerConfig};
use linkerd_io::{AsyncRead, AsyncWrite, Result, PeerAddr, ReadBuf};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use crate::{HasNegotiatedProtocol, NegotiatedProtocolRef, ClientId};
use openssl::ssl;
use openssl::ssl::{SslConnector, SslMethod, Ssl, SslAcceptor};
use std::net::SocketAddr;

#[derive(Clone)]
pub struct TlsConnector(ssl::SslConnector);

impl TlsConnector {
    pub fn new(_conf: Arc<ClientConfig>) -> Self {
        let conn = SslConnector::builder(SslMethod::tls())
            .unwrap()
            .build();
        Self(conn)
    }

    pub async fn connect<IO>(&self, domain: Name, stream: IO) -> Result<client::TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let ssl = self.0
            .configure()
            .unwrap()
            .into_ssl(domain.as_ref())
            .unwrap();
        let mut s = TlsStream::new(ssl, stream);
        Pin::new(&mut s.0).connect().await.unwrap();
        Ok(s)
    }
}

#[derive(Clone)]
pub struct TlsAcceptor(ssl::SslAcceptor);

impl TlsAcceptor {
    pub fn new(_conf: Arc<ServerConfig>) -> Self {
        let acc = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
        Self(acc.build())
    }

    pub async fn accept<IO>(&self, stream: IO) -> Result<server::TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let ssl = Ssl::new(self.0.context()).unwrap();
        let mut s = TlsStream::new(ssl, stream);

        Pin::new(&mut s.0).accept().await.unwrap();
        Ok(s)
    }
}

#[derive(Debug)]
pub struct TlsStream<IO>(tokio_openssl::SslStream<IO>);

impl<IO> TlsStream<IO>
    where
        IO: AsyncRead + AsyncWrite,
{
    pub fn new(ssl: Ssl, stream: IO) -> Self {
        Self(tokio_openssl::SslStream::new(ssl, stream).unwrap())
    }
}

impl<IO> TlsStream<IO> {
    pub fn get_alpn_protocol(&self) -> Option<&[u8]> {
        self.0.ssl().selected_alpn_protocol()
    }

    pub fn client_identity(&self) -> Option<ClientId> {
        None
    }
}

impl<IO> From<tokio_openssl::SslStream<IO>> for TlsStream<IO> {
    fn from(stream: tokio_openssl::SslStream<IO>) -> Self {
        TlsStream(stream)
    }
}

impl<IO: PeerAddr> PeerAddr for TlsStream<IO> {
    fn peer_addr(&self) -> Result<SocketAddr> {
        unimplemented!()
    }
}

impl<IO> HasNegotiatedProtocol for TlsStream<IO> {
    #[inline]
    fn negotiated_protocol(&self) -> Option<NegotiatedProtocolRef<'_>> {
        unimplemented!()
    }
}

impl<IO> AsyncRead for TlsStream<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<IO> AsyncWrite for TlsStream<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub mod client {
    pub use super::TlsStream;
}

pub mod server {
    pub use super::TlsStream;
}

// mod tests {
//     use std::net::ToSocketAddrs;
//     use linkerd_io::{AsyncWriteExt, AsyncReadExt};
//     use super::TlsConnector;
//     use linkerd_identity::{Name, ClientConfig};
//     use std::sync::Arc;
//     use std::str::FromStr;
//     use tokio::net::TcpStream;
//
//     #[tokio::test]
//     async fn google() {
//         let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
//         let stream = TcpStream::connect(&addr).await.unwrap();
//         let connector = TlsConnector::new(Arc::new(ClientConfig::empty()));
//         let domain = Name::from_str("google.com").unwrap();
//         let mut stream = connector.connect(domain, stream).await.unwrap();
//
//         // Pin::new(&mut stream).connect().await.unwrap();
//         stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
//
//         let mut buf = vec![];
//         stream.read_to_end(&mut buf).await.unwrap();
//         let response = String::from_utf8_lossy(&buf);
//         let response = response.trim_end();
//         //
//         // any response code is fine
//         assert!(response.starts_with("HTTP/1.0 "));
//         assert!(response.ends_with("</html>") || response.ends_with("</HTML>"));
//     }
// }
