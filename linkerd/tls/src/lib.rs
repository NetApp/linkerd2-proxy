#![deny(warnings, rust_2018_idioms)]

use linkerd_identity as id;
pub use id::LocalId;
use linkerd_io as io;
pub use rustls::Session;

#[cfg(not(feature = "openssl"))]
#[path = "imp/rustls.rs"]
mod imp;

pub mod client;
pub mod server;

pub use self::{
    client::{Client, ClientTls, ConditionalClientTls, NoClientTls, ServerId},
    server::{ClientId, ConditionalServerTls, NewDetectTls, NoServerTls, ServerTls},
};
use core::fmt;
use std::sync::Arc;

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

impl<I> HasNegotiatedProtocol for self::server::TlsStream<I> {
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

#[derive(Clone, Debug)]
pub struct TlsConnector(imp::TlsConnector);

impl TlsConnector {
    pub fn new(conf: Arc<id::ClientConfig>) -> Self {
        Self(imp::TlsConnector::new(conf))
    }
}

impl From<Arc<id::ClientConfig>> for TlsConnector {
    fn from(conf: Arc<id::ClientConfig>) -> Self {
        TlsConnector::new(conf.clone())
    }
}

/// A stream managing a TLS session.
pub struct TlsStream<S>(imp::TlsStream<S>);

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> TlsStream<S> {
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}
