use futures::Future;
use linkerd_identity::{ClientConfig, Name, ServerConfig};
use linkerd_io::{AsyncRead, AsyncWrite};
use std::{error, fmt, io};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
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
        Connect(self.0.connect(dns, stream))
    }
}

pub struct Connect<IO>(tokio_rustls::Connect<IO>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = io::Result<client::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|f| {
            debug!("Connect poll on accept implemenation");
            match f {
                Ok(stream) => Ok(stream.into()),
                Err(err) => Err(err)
            }
        })
    }
}

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

pub mod client {
    use std::{
        io,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };

    use linkerd_io::{AsyncRead, AsyncWrite, PeerAddr, ReadBuf};
    use rustls::Session;
    use tracing::debug;

    use crate::{HasNegotiatedProtocol, NegotiatedProtocolRef};

    #[derive(Debug)]
    pub struct TlsStream<IO>(tokio_rustls::client::TlsStream<IO>);

    impl<IO> From<tokio_rustls::client::TlsStream<IO>> for TlsStream<IO> {
        fn from(stream: tokio_rustls::client::TlsStream<IO>) -> Self {
            debug!("Converting from tokio_rusls client tls stream");
            TlsStream(stream)
        }
    }

    impl<IO: PeerAddr> PeerAddr for TlsStream<IO> {
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.0.get_ref().0.peer_addr()
        }
    }

    impl<IO> HasNegotiatedProtocol for TlsStream<IO> {
        #[inline]
        fn negotiated_protocol(&self) -> Option<NegotiatedProtocolRef<'_>> {
            self.0
                .get_ref()
                .1
                .get_alpn_protocol()
                .map(NegotiatedProtocolRef)
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
            debug!("Poll read on tls client implemenation");
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
            debug!("Poll write tls client stream implemenation");
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            debug!("Poll flush on tls client stream implemenation");
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            debug!("Poll flush on tls client stream implemenation");
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
}

pub mod server {
    use std::{
        io,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };

    use linkerd_dns_name as dns;
    use linkerd_identity::Name;
    use linkerd_io::{AsyncRead, AsyncWrite, PeerAddr, ReadBuf};
    use rustls::Session;
    use tracing::debug;

    use crate::{ClientId, HasNegotiatedProtocol, NegotiatedProtocolRef};

    #[derive(Debug)]
    pub struct TlsStream<IO>(tokio_rustls::server::TlsStream<IO>);

    impl<IO> TlsStream<IO> {
        pub fn client_identity(&self) -> Option<ClientId> {
            use webpki::GeneralDNSNameRef;

            let (_io, session) = self.0.get_ref();
            let certs = session.get_peer_certificates()?;
            let c = certs.first().map(rustls::Certificate::as_ref)?;
            let end_cert = webpki::EndEntityCert::from(c).ok()?;
            let dns_names = end_cert.dns_names().ok()?;

            match dns_names.first()? {
                GeneralDNSNameRef::DNSName(n) => {
                    Some(ClientId(Name::from(dns::Name::from(n.to_owned()))))
                }
                GeneralDNSNameRef::Wildcard(_) => {
                    // Wildcards can perhaps be handled in a future path...
                    None
                }
            }
        }
    }

    impl<IO> From<tokio_rustls::server::TlsStream<IO>> for TlsStream<IO> {
        fn from(stream: tokio_rustls::server::TlsStream<IO>) -> Self {
            debug!("Converting from tokio_rusls tls stream");
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
            debug!("Poll read on tls stream implemenation");
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
            debug!("Poll write tls stream implemenation");
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            debug!("Poll flush on tls stream implemenation");
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            debug!("Poll flush on tls stream implemenation");
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl<IO> HasNegotiatedProtocol for TlsStream<IO> {
        #[inline]
        fn negotiated_protocol(&self) -> Option<NegotiatedProtocolRef<'_>> {
            self.0
                .get_ref()
                .1
                .get_alpn_protocol()
                .map(|b| NegotiatedProtocolRef(b.into()))
        }
    }
}

pub struct Accept<IO>(tokio_rustls::Accept<IO>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<server::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|f| {
            debug!("Accept poll on accept implemenation");
            let stream: server::TlsStream<IO> = f.unwrap().into();
            Ok(stream)
        })
    }
}
