use crate::{ClientId, HasNegotiatedProtocol, NegotiatedProtocolRef};
use linkerd_identity::{ClientConfig, Name, ServerConfig};
use linkerd_io::{AsyncRead, AsyncWrite, Error, ErrorKind, PeerAddr, ReadBuf, Result};
use std::net::SocketAddr;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use {
    boring::{
        ssl,
        ssl::{SslAcceptor, SslAcceptorBuilder, SslConnector, SslConnectorBuilder, SslMethod},
    },
    tokio_boring::SslStream,
};

#[derive(Clone)]
pub struct TlsConnector(ssl::SslConnector);

impl TlsConnector {
    pub async fn connect<IO>(&self, domain: Name, stream: IO) -> Result<client::TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let conf = self
            .0
            .configure()
            .unwrap();
        match tokio_boring::connect(conf, domain.as_ref(), stream).await {
            Ok(ss) => Ok(ss.into()),
            Err(_err) => {
                println!("Handshake error");
                Err(Error::new(ErrorKind::Other, "Connection problem"))
            }
        }
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
        match tokio_boring::accept(&self.0, stream).await {
            Ok(ss) => Ok(ss.into()),
            Err(_err) => {
                println!("Handshake error");
                Err(Error::new(ErrorKind::Other, "Connection problem"))
            }
        }
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
        Pin::new(&mut self.0.get_mut()).poll_flush(cx)
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
