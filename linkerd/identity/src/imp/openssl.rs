use crate::{LocalId, Name};
use openssl::{ec::{EcKey}, error::ErrorStack, pkey::{self, PKey, Private}, x509::{
        store::{X509Store, X509StoreBuilder},
        X509,
    }};
use std::sync::Arc;
use std::time::SystemTime;
use std::{error, fmt};
use tracing::{debug, warn};

#[derive(Clone)]
pub struct Key {
   inner: Arc<EcKey<Private>>,
   pub id: pkey::Id,
}

impl Key {
    pub fn from_pkcs8(b: &[u8]) -> Result<Key, Error> {
        let key= PKey::private_key_from_pkcs8(b).unwrap();
        let private_key = key.ec_key().unwrap();

        Ok(Key {
            inner: Arc::new(private_key),
            id: key.id()
        })
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "key id {}", self.id.as_raw())
    }
}

pub struct Error(ErrorStack);

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Error(err)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        error::Error::source(&self.0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

#[derive(Clone)]
pub struct TrustAnchors(Arc<X509Store>);

impl TrustAnchors {
    #[cfg(any(test, feature = "test-util"))]
    pub fn empty() -> Self {
        unimplemented!()
    }

    pub fn from_pem(s: &str) -> Option<Self> {
        let mut store = X509StoreBuilder::new().unwrap();

        match X509::from_pem(s.as_bytes()) {
            Ok(cert) => {
                debug!("Adding trust {:?}", cert);
                store.add_cert(cert).unwrap();
            }
            Err(err) => warn!("unable to construct trust anchor {}", err),
        }

        Some(Self(Arc::new(store.build())))
    }

    pub fn certify(&self, _: Key, crt: Crt) -> Result<CrtKey, InvalidCrt> {
        Ok(CrtKey {
            id: crt.id,
            expiry: crt.expiry,
            client_config: Arc::new(ClientConfig),
            server_config: Arc::new(ServerConfig),
        })
    }

    pub fn client_config(&self) -> Arc<ClientConfig> {
        Arc::new(ClientConfig)
    }
}

#[derive(Clone, Debug)]
pub struct InvalidCrt(String);

impl fmt::Display for InvalidCrt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl error::Error for InvalidCrt {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // self.0.source()
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct CrtKey {
    id: LocalId,
    expiry: SystemTime,
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
}

// === CrtKey ===
impl CrtKey {
    pub fn name(&self) -> &Name {
        self.id.as_ref()
    }

    pub fn expiry(&self) -> SystemTime {
        self.expiry
    }

    pub fn id(&self) -> &LocalId {
        &self.id
    }

    pub fn client_config(&self) -> Arc<ClientConfig> {
        self.client_config.clone()
    }

    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.server_config.clone()
    }
}

impl fmt::Debug for CrtKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("CrtKey")
            .field("id", &self.id)
            .field("expiry", &self.expiry)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct Crt {
    pub(crate) id: LocalId,
    expiry: SystemTime,
    chain: Vec<X509>,
}

impl Crt {
    pub fn new(
        id: LocalId,
        leaf: Vec<u8>,
        intermediates: Vec<Vec<u8>>,
        expiry: SystemTime,
    ) -> Self {
        let mut chain = Vec::with_capacity(intermediates.len() + 1);
        let cert = X509::from_der(&leaf).unwrap();
        chain.push(cert);
        chain.extend(
            intermediates
                .into_iter()
                .map(|crt| X509::from_der(&crt).unwrap()),
        );

        Self { id, chain, expiry }
    }

    pub fn name(&self) -> &Name {
        self.id.as_ref()
    }
}

#[derive(Clone)]
pub struct ClientConfig;

impl ClientConfig {
    pub fn set_protocols(&mut self, _protocols: Vec<Vec<u8>>) {
        unimplemented!()
    }
}

// impl Into<Arc<rustls::ClientConfig>> for ClientConfig {
//     fn into(self) -> Arc<rustls::ClientConfig> {
//         Arc::new(self.into())
//     }
// }

// impl Into<rustls::ClientConfig> for ClientConfig {
//     fn into(self) -> rustls::ClientConfig {
//         self.0
//     }
// }

// impl AsRef<rustls::ClientConfig> for ClientConfig {
//     fn as_ref(&self) -> &rustls::ClientConfig {
//         &self.0
//     }
// }

#[derive(Clone)]
pub struct ServerConfig;

impl ServerConfig {
    /// Produces a server config that fails to handshake all connections.
    pub fn empty() -> Self {
        unimplemented!()
    }

    pub fn add_protocols(&mut self, _protocols: Vec<u8>) {
        unimplemented!()
    }
}

// impl Into<Arc<rustls::ServerConfig>> for ServerConfig {
//     fn into(self) -> Arc<rustls::ServerConfig> {
//         Arc::new(self.into())
//     }
// }

// impl Into<rustls::ServerConfig> for ServerConfig {
//     fn into(self) -> rustls::ServerConfig {
//         self.0
//     }
// }

// impl AsRef<rustls::ServerConfig> for ServerConfig {
//     fn as_ref(&self) -> &rustls::ServerConfig {
//         &self.0
//     }
// }
