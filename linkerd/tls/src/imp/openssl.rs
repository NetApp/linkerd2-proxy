use futures::Future;
use linkerd_identity::{ClientConfig, Name, ServerConfig};
use linkerd_io::{AsyncRead, AsyncWrite, Result};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[derive(Clone)]
pub struct TlsConnector(tokio_native_tls::TlsConnector);

impl TlsConnector {
    pub fn new(_conf: Arc<ClientConfig>) -> Self {
        let conn = tokio_native_tls::native_tls::TlsConnector::new().unwrap();
        conn.into()
    }

    pub fn connect<IO>(&self, domain: Name, stream: IO) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let x = self.0.connect(domain.as_ref().into(), stream).unwrap();
        Connect(x)
    }
}

impl From<tokio_native_tls::native_tls::TlsConnector> for TlsConnector {
    fn from(conn: tokio_native_tls::native_tls::TlsConnector) -> Self {
        Self(conn.into())
    }
}

pub struct Connect<IO>(tokio_native_tls::TlsStream<IO>);

impl<IO> Future for Connect<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<client::TlsStream<IO>>;

    #[inline]
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(self.0.into()))
    }
}

#[derive(Clone)]
pub struct TlsAcceptor;

impl TlsAcceptor {
    pub fn new(_conf: Arc<ServerConfig>) -> Self {
        unimplemented!()
    }

    pub fn accept<IO>(&self, _stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        unimplemented!()
    }
}

pub mod client {
    use std::{
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };

    use linkerd_io::{AsyncRead, AsyncWrite, PeerAddr, ReadBuf, Result};

    use crate::{HasNegotiatedProtocol, NegotiatedProtocolRef};

    #[derive(Debug)]
    pub struct TlsStream<IO>(tokio_native_tls::TlsStream<IO>);

    impl<IO> TlsStream<IO> {
        pub fn get_alpn_protocol(&self) -> Option<&[u8]> {
            unimplemented!()
        }
    }

    impl<IO> From<tokio_native_tls::TlsStream<IO>> for TlsStream<IO> {
        fn from(stream: tokio_native_tls::TlsStream<IO>) -> Self {
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
}

pub mod server {
    use std::{
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };

    use linkerd_io::{AsyncRead, AsyncWrite, PeerAddr, ReadBuf, Result};

    use crate::{ClientId, HasNegotiatedProtocol, NegotiatedProtocolRef};

    #[derive(Debug)]
    pub struct TlsStream<IO>(IO);

    impl<IO> TlsStream<IO> {
        pub fn client_identity(&self) -> Option<ClientId> {
            unimplemented!()
        }
    }

    // impl<IO> From<tokio_rustls::server::TlsStream<IO>> for TlsStream<IO> {
    //     fn from(stream: tokio_rustls::server::TlsStream<IO>) -> Self {
    //         TlsStream(stream)
    //     }
    // }

    impl<IO: PeerAddr> PeerAddr for TlsStream<IO> {
        fn peer_addr(&self) -> Result<SocketAddr> {
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

    impl<IO> HasNegotiatedProtocol for TlsStream<IO> {
        #[inline]
        fn negotiated_protocol(&self) -> Option<NegotiatedProtocolRef<'_>> {
            unimplemented!()
        }
    }
}

pub struct Accept<IO>(IO);

impl<IO> Future for Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<server::TlsStream<IO>>;

    #[inline]
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        unimplemented!()
        // Pin::new(&mut self.0).poll(cx).map(|f| match f {
        //     Ok(stream) => Ok(stream.into()),
        //     Err(err) => Err(err),
        // })
    }
}
