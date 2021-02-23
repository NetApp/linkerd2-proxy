use std::sync::Arc;
use std::{io, error, fmt};
use linkerd_io::{AsyncRead, AsyncWrite};
use tokio_rustls::{Accept, Connect};
use tracing::{debug};
use linkerd_identity::{ClientConfig, ServerConfig, Name};
use webpki::DNSNameRef;


pub struct HandshakeError(io::Error);

impl error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        error::Error::source(&self.0)
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

impl fmt::Debug for HandshakeError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

#[derive(Clone)]
pub struct TlsConnector(tokio_rustls::TlsConnector);

impl TlsConnector {
    pub fn new(conf: Arc<ClientConfig>) -> Self {
        let rustls_config: Arc<rustls::ClientConfig> = conf.as_ref().clone().0.into();
        debug!("Constructing TlsConnector");
        Self(tokio_rustls::TlsConnector::from(rustls_config))
    }

    pub fn connect<IO>(&self, domain: Name, stream: IO) -> Connect<IO>
        where
            IO: AsyncRead + AsyncWrite + Unpin,
    {
        // TODO: Remove before integration
        debug!(imp="rustls", "Connecting");
        let dns = DNSNameRef::try_from_ascii_str(domain.as_ref()).unwrap();
        self.0.connect(dns, stream)
    }
}

pub struct TlsStream<S>(tokio_rustls::TlsStream<S>);

// pub struct Connect<IO>(tokio_rustls::Connect<IO>);

// impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
//     type Output = io::Result<TlsStream<IO>>;
//
//     #[inline]
//     fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
//     }
// }

#[derive(Clone)]
pub struct TlsAcceptor(tokio_rustls::TlsAcceptor);

impl TlsAcceptor {
    pub fn new(conf: Arc<ServerConfig>) -> Self {
        let rustls_config: Arc<rustls::ServerConfig> = conf.as_ref().clone().0.into();
        // TODO: Remove before integration
        debug!(imp="rustls", "Constructing TlsAcceptor");
        Self(tokio_rustls::TlsAcceptor::from(rustls_config))
    }

    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
        where
            IO: AsyncRead + AsyncWrite + Unpin
    {
        // TODO: Remove before integration
        debug!(imp="rustls", "Accepting connection");
        self.0.accept(stream)
    }
}