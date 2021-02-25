use futures::Future;
use linkerd_identity::{ClientConfig, Name, ServerConfig};
use linkerd_io::{AsyncRead, AsyncWrite};
use std::{error, fmt, io};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio_rustls::Connect;
use tracing::debug;
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
        debug!(imp = "rustls", "Connecting");
        let dns = DNSNameRef::try_from_ascii_str(domain.as_ref()).unwrap();
        self.0.connect(dns, stream)
    }
}

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
        debug!(imp = "rustls", "Constructing TlsAcceptor");
        Self(tokio_rustls::TlsAcceptor::from(rustls_config))
    }

    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // TODO: Remove before integration
        debug!(imp = "rustls", "Accepting connection");
        Accept(self.0.accept(stream))
    }
}

// pub mod client {
//     pub struct TlsStream<S>(tokio_rustls::client::TlsStream<S>);
// }

pub mod server {
    use std::{
        io,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };

    use linkerd_io::{AsyncRead, AsyncWrite, PeerAddr, ReadBuf};

    #[derive(Debug)]
    pub struct TlsStream<IO>(tokio_rustls::server::TlsStream<IO>);

    impl<IO> From<tokio_rustls::server::TlsStream<IO>> for TlsStream<IO> {
        fn from(stream: tokio_rustls::server::TlsStream<IO>) -> Self {
            TlsStream(stream)
        }
    }

    impl<IO: PeerAddr> PeerAddr for TlsStream<IO> {
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.0.get_ref().0.peer_addr()
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
        ) -> Poll<io::Result<()>> {
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
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
}

pub struct Accept<IO>(tokio_rustls::Accept<IO>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<server::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|f| {
            let stream: server::TlsStream<IO> = f.unwrap().into();
            Ok(stream)
        })
    }
}
