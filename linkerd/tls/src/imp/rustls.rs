use linkerd_identity as id;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct TlsConnector(tokio_rustls::TlsConnector);

impl TlsConnector {
    pub fn new(conf: Arc<id::ClientConfig>) -> Self {
        Self(tokio_rustls::TlsConnector::from(Arc::new(conf.0.into())))
    }
}

pub struct TlsStream<S>(tokio_rustls::TlsStream<S>);
