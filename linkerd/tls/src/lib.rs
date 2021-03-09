#![deny(warnings, rust_2018_idioms)]

pub use linkerd_identity::LocalId;
use linkerd_identity::{ClientConfig, Name, ServerConfig};
use linkerd_io as io;
use linkerd_io::{AsyncRead, AsyncWrite};

#[cfg(feature = "rustls-tls")]
#[path = "imp/rustls.rs"]
mod imp;
#[cfg(feature = "openssl-tls")]
#[path = "imp/openssl.rs"]
mod imp;

mod protocol;

pub mod client;
pub mod server;

pub use self::{
    client::{Client, ClientTls, ConditionalClientTls, NoClientTls, ServerId},
    protocol::{HasNegotiatedProtocol, NegotiatedProtocol, NegotiatedProtocolRef},
    server::{ClientId, ConditionalServerTls, NewDetectTls, NoServerTls, ServerTls},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct TlsConnector(imp::TlsConnector);

impl TlsConnector {
    pub async fn connect<IO>(&self, domain: Name, stream: IO) -> io::Result<client::TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        Ok(self.0.connect(domain, stream).await.unwrap().into())
    }
}

impl From<imp::TlsConnector> for TlsConnector {
    fn from(connector: imp::TlsConnector) -> Self {
        TlsConnector(connector)
    }
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(conf: Arc<ClientConfig>) -> Self {
        imp::TlsConnector::from(conf).into()
    }
}

#[derive(Clone)]
pub struct TlsAcceptor(imp::TlsAcceptor);

impl TlsAcceptor {
    pub async fn accept<IO>(&self, stream: IO) -> io::Result<server::TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        Ok(self.0.accept(stream).await.unwrap().into())
    }
}

impl From<imp::TlsAcceptor> for TlsAcceptor {
    fn from(acceptor: imp::TlsAcceptor) -> Self {
        TlsAcceptor(acceptor)
    }
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(conf: Arc<ServerConfig>) -> Self {
        imp::TlsAcceptor::from(conf).into()
    }
}
