#![deny(warnings, rust_2018_idioms)]

use futures::Future;
pub use linkerd_identity::LocalId;
use linkerd_identity::{ClientConfig, Name, ServerConfig};
use linkerd_io as io;
use linkerd_io::{AsyncRead, AsyncWrite};
use tracing::debug;

#[cfg(not(feature = "openssl"))]
#[path = "imp/rustls.rs"]
mod imp;

pub mod client;
pub mod server;
mod protocol;

pub use self::{
    client::{Client, ClientTls, ConditionalClientTls, NoClientTls, ServerId},
    server::{ClientId, ConditionalServerTls, NewDetectTls, NoServerTls, ServerTls},
    protocol::{NegotiatedProtocol, NegotiatedProtocolRef, HasNegotiatedProtocol},
};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};


#[derive(Clone)]
pub struct TlsConnector(imp::TlsConnector);

impl TlsConnector {
    pub fn new(conf: Arc<ClientConfig>) -> Self {
        Self(imp::TlsConnector::new(conf))
    }

    pub fn connect<IO>(&self, domain: Name, stream: IO) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // TODO: Remove before integration
        debug!(%domain, "Connecting to ");
        Connect(self.0.connect(domain, stream))
    }
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(conf: Arc<ClientConfig>) -> Self {
        TlsConnector::new(conf.clone())
    }
}

pub struct Connect<IO>(imp::Connect<IO>);

impl<IO> Future for Connect<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<client::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|f| match f {
            Ok(stream) => Ok(stream.into()),
            Err(err) => Err(err),
        })
    }
}

#[derive(Clone)]
pub struct TlsAcceptor(imp::TlsAcceptor);

impl TlsAcceptor {
    pub fn new(conf: Arc<ServerConfig>) -> Self {
        Self(imp::TlsAcceptor::new(conf))
    }

    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // TODO: Remove before integration
        debug!("Accepting connection");
        Accept(self.0.accept(stream))
    }
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(conf: Arc<ServerConfig>) -> Self {
        TlsAcceptor::new(conf.clone())
    }
}

/// Future returned from `TlsAcceptor::accept` which will resolve
/// once the accept handshake has finished.
pub struct Accept<IO>(imp::Accept<IO>);

impl<IO> Future for Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<server::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|f| match f {
            Ok(stream) => Ok(stream.into()),
            Err(err) => Err(err),
        })
    }
}
