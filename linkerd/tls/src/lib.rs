#![deny(warnings, rust_2018_idioms)]

use futures::Future;
pub use id::LocalId;
use linkerd_identity as id;
use linkerd_io as io;
use linkerd_io::{AsyncRead, AsyncWrite};
pub use rustls::Session;
pub use tokio_rustls::Connect;
use tracing::debug;

#[cfg(not(feature = "openssl"))]
#[path = "imp/rustls.rs"]
mod imp;

pub mod client;
pub mod server;

pub use self::{
    client::{Client, ClientTls, ConditionalClientTls, NoClientTls, ServerId},
    server::{ClientId, ConditionalServerTls, NewDetectTls, NoServerTls, ServerTls},
};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use linkerd_identity::Name;

/// A trait implented by transport streams to indicate its negotiated protocol.
pub trait HasNegotiatedProtocol {
    fn negotiated_protocol(&self) -> Option<NegotiatedProtocolRef<'_>>;
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct NegotiatedProtocol(pub Vec<u8>);

/// Indicates a negotiated protocol.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct NegotiatedProtocolRef<'t>(pub &'t [u8]);

impl NegotiatedProtocol {
    pub fn as_ref(&self) -> NegotiatedProtocolRef<'_> {
        NegotiatedProtocolRef(&self.0)
    }
}

impl std::fmt::Debug for NegotiatedProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        NegotiatedProtocolRef(&self.0).fmt(f)
    }
}

impl NegotiatedProtocolRef<'_> {
    pub fn to_owned(&self) -> NegotiatedProtocol {
        NegotiatedProtocol(self.0.into())
    }
}

impl Into<NegotiatedProtocol> for NegotiatedProtocolRef<'_> {
    fn into(self) -> NegotiatedProtocol {
        self.to_owned()
    }
}

impl std::fmt::Debug for NegotiatedProtocolRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match std::str::from_utf8(self.0) {
            Ok(s) => s.fmt(f),
            Err(_) => self.0.fmt(f),
        }
    }
}

impl<I> HasNegotiatedProtocol for self::client::TlsStream<I> {
    #[inline]
    fn negotiated_protocol(&self) -> Option<NegotiatedProtocolRef<'_>> {
        self.get_ref()
            .1
            .get_alpn_protocol()
            .map(NegotiatedProtocolRef)
    }
}

impl HasNegotiatedProtocol for tokio::net::TcpStream {
    #[inline]
    fn negotiated_protocol(&self) -> Option<NegotiatedProtocolRef<'_>> {
        None
    }
}

impl<I: HasNegotiatedProtocol> HasNegotiatedProtocol for io::ScopedIo<I> {
    #[inline]
    fn negotiated_protocol(&self) -> Option<NegotiatedProtocolRef<'_>> {
        self.get_ref().negotiated_protocol()
    }
}

impl<L, R> HasNegotiatedProtocol for io::EitherIo<L, R>
where
    L: HasNegotiatedProtocol,
    R: HasNegotiatedProtocol,
{
    #[inline]
    fn negotiated_protocol(&self) -> Option<NegotiatedProtocolRef<'_>> {
        match self {
            io::EitherIo::Left(l) => l.negotiated_protocol(),
            io::EitherIo::Right(r) => r.negotiated_protocol(),
        }
    }
}

#[derive(Clone)]
pub struct TlsConnector(imp::TlsConnector);

impl TlsConnector {
    pub fn new(conf: Arc<id::ClientConfig>) -> Self {
        Self(imp::TlsConnector::new(conf))
    }

    pub fn connect<IO>(&self, domain: Name, stream: IO) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // TODO: Remove before integration
        debug!(%domain, "Connecting to ");
        self.0.connect(domain, stream)
    }
}

impl From<Arc<id::ClientConfig>> for TlsConnector {
    fn from(conf: Arc<id::ClientConfig>) -> Self {
        TlsConnector::new(conf.clone())
    }
}

#[derive(Clone)]
pub struct TlsAcceptor(imp::TlsAcceptor);

impl TlsAcceptor {
    pub fn new(conf: Arc<id::ServerConfig>) -> Self {
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

impl From<Arc<id::ServerConfig>> for TlsAcceptor {
    fn from(conf: Arc<id::ServerConfig>) -> Self {
        TlsAcceptor::new(conf.clone())
    }
}

/// Future returned from `TlsAcceptor::accept` which will resolve
/// once the accept handshake has finished.
pub struct Accept<IO>(imp::Accept<IO>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<server::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|f| {
            let ble: server::TlsStream<IO> = f.unwrap().into();
            Ok(ble)
        })
    }
}
