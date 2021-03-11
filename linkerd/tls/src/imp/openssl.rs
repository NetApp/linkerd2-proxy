use crate::{ClientId, HasNegotiatedProtocol, NegotiatedProtocolRef};
use linkerd_identity::{ClientConfig, Name, ServerConfig};
use linkerd_io::{AsyncRead, AsyncWrite, PeerAddr, ReadBuf, Result};
use std::net::SocketAddr;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use {
    openssl::{
        ssl,
        ssl::{Ssl, SslAcceptor, SslAcceptorBuilder, SslConnector, SslConnectorBuilder, SslMethod},
    },
    tokio_openssl::SslStream,
};

#[derive(Clone)]
pub struct TlsConnector(ssl::SslConnector);

impl TlsConnector {
    pub async fn connect<IO>(&self, domain: Name, stream: IO) -> Result<client::TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let ssl = self
            .0
            .configure()
            .unwrap()
            .into_ssl(domain.as_ref())
            .unwrap();
        let mut s = TlsStream::new(ssl, stream);
        Pin::new(&mut s.0).connect().await.unwrap();
        Ok(s)
    }
}

impl From<SslConnector> for TlsConnector {
    fn from(connector: SslConnector) -> Self {
        Self(connector)
    }
}

impl From<SslConnectorBuilder> for TlsConnector {
    fn from(builder: SslConnectorBuilder) -> Self {
        builder.build().into()
    }
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(_conf: Arc<ClientConfig>) -> Self {
        SslConnector::builder(SslMethod::tls()).unwrap().into()
    }
}

#[derive(Clone)]
pub struct TlsAcceptor(ssl::SslAcceptor);

impl TlsAcceptor {
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

impl From<SslAcceptor> for TlsAcceptor {
    fn from(acceptor: SslAcceptor) -> Self {
        Self(acceptor)
    }
}

impl From<SslAcceptorBuilder> for TlsAcceptor {
    fn from(builder: SslAcceptorBuilder) -> Self {
        builder.build().into()
    }
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(_conf: Arc<ServerConfig>) -> Self {
        SslAcceptor::mozilla_modern(SslMethod::tls())
            .unwrap()
            .into()
    }
}

#[derive(Debug)]
pub struct TlsStream<IO>(SslStream<IO>);

impl<IO> TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite,
{
    pub fn new(ssl: Ssl, stream: IO) -> Self {
        Self(SslStream::new(ssl, stream).unwrap())
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

impl<IO> From<SslStream<IO>> for TlsStream<IO> {
    fn from(stream: SslStream<IO>) -> Self {
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
//     use super::TlsConnector;
//     use crate::imp::TlsAcceptor;
//     use linkerd_identity::{ClientConfig, Name, ServerConfig};
//     use linkerd_io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
//     use std::pin::Pin;
//     use std::str::FromStr;
//     use std::sync::Arc;
//     use tokio::net::{TcpListener, TcpStream};
//     use std::net::ToSocketAddrs;
//
//     #[tokio::test]
//     async fn google() {
//         let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
//         let stream = TcpStream::connect(&addr).await.unwrap();
//         let connector = TlsConnector::from(Arc::new(ClientConfig::empty()));
//         let domain = Name::from_str("google.com").unwrap();
//         let mut stream = connector.connect(domain, stream).await.unwrap();
//
//         stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
//
//         let mut buf = vec![];
//         stream.read_to_end(&mut buf).await.unwrap();
//         let response = String::from_utf8_lossy(&buf);
//         let response = response.trim_end();

// any response code is fine
// assert!(response.starts_with("HTTP/1.0 "));
// assert!(response.ends_with("</html>") || response.ends_with("</HTML>"));
// }
//
// #[tokio::test]
// async fn server() {
//     let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
//     let addr = listener.local_addr().unwrap();
//
//     let server = async move {
//         let acceptor = TlsAcceptor::from(Arc::new(ServerConfig::empty()));
//
//         let stream = listener.accept().await.unwrap().0;
//         let mut stream = acceptor.accept(stream).await.unwrap();
//
//         let mut buf = [0; 4];
//         stream.read_exact(&mut buf).await.unwrap();
//         assert_eq!(&buf, b"asdf");
//
//         stream.write_all(b"jkl;").await.unwrap();
//
//         futures::future::poll_fn(|ctx| Pin::new(&mut stream).poll_shutdown(ctx))
//             .await
//             .unwrap()
//     };
//
//     let client = async {
//         let connector = TlsConnector::from(Arc::new(ClientConfig::empty()));
//         let name = Name::from_str("localhost").unwrap();
//
//         let stream = TcpStream::connect(&addr).await.unwrap();
//         let mut stream = connector.connect(name, stream).await.unwrap();
//
//         stream.write_all(b"asdf").await.unwrap();
//
//         let mut buf = vec![];
//         stream.read_to_end(&mut buf).await.unwrap();
//         assert_eq!(buf, b"jkl;");
//     };
//
//     futures::future::join(server, client).await;
// }
// }
