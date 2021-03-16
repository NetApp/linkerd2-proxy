use std::sync::Arc;
use std::time::SystemTime;
use std::{error, fmt};

#[cfg(feature = "boring-tls")]
use boring::{
    error::ErrorStack,
    pkey::{PKey, Private},
    stack::Stack,
    x509::{
        {X509, X509StoreContext, X509VerifyResult},
        store::{X509Store, X509StoreBuilder},
    },
};
#[cfg(not(feature = "boring-tls"))]
use openssl::{
    error::ErrorStack,
    pkey::{PKey, Private},
    stack::Stack,
    x509::{
        {X509, X509StoreContext, X509VerifyResult},
        store::{X509Store, X509StoreBuilder},
    },
};

use tracing::{debug, warn};

use crate::{LocalId, Name};

#[derive(Clone, Debug)]
pub struct Key(Arc<PKey<Private>>);

impl Key {
    pub fn from_pkcs8(b: &[u8]) -> Result<Key, Error> {
        let key = PKey::private_key_from_pkcs8(b)?;
        Ok(Key(Arc::new(key)))
    }
}

#[derive(Clone, Debug)]
pub struct Error(ErrorStack);

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Self(err)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.0.source()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, fmt)
    }
}

#[derive(Clone)]
pub struct TrustAnchors(Arc<X509Store>);

impl TrustAnchors {
    #[cfg(any(test, feature = "test-util"))]
    pub fn empty() -> Self {
        Self(Arc::new(X509StoreBuilder::new().unwrap().build()))
    }

    pub fn from_pem(s: &str) -> Option<Self> {
        debug!("Loading {} into x509", s);
        let mut store = X509StoreBuilder::new().unwrap();

        match X509::from_pem(s.as_bytes()) {
            Ok(cert) => {
                println!("Adding trust {:?}", cert);
                store.add_cert(cert).unwrap();
            }
            Err(err) => warn!("unable to construct trust anchor {}", err),
        }

        Some(Self(Arc::new(store.build())))
    }

    pub fn certify(&self, _: Key, crt: Crt) -> Result<CrtKey, InvalidCrt> {
        let cert = crt.cert.clone();
        if cert.subject_alt_names()
            .unwrap()
            .iter()
            .filter(|n| n.dnsname().unwrap().to_string() == crt.id.to_string())
            .next().is_none() {
            return Err(InvalidCrt::SubjectAltName(crt.id.to_string()));
        }

        let mut chain = Stack::new().unwrap();
        for chain_crt in crt.chain.clone() {
            chain.push(chain_crt).unwrap();
        }

        let mut context = X509StoreContext::new().unwrap();
        match context.init(&self.0, &cert, &chain, |c| {
            match c.verify_cert() {
                Ok(true) => {
                    Ok(Ok(true))
                }
                Ok(false) => {
                    Ok(Err(InvalidCrt::Verify(c.error())))
                }
                Err(err) => Err(err),
            }
        }) {
            Ok(verify) => {
                match verify {
                    Ok(_) => Ok(CrtKey {
                        id: crt.id.clone(),
                        expiry: crt.expiry.clone(),
                        client_config: Arc::new(ClientConfig::empty()),
                        server_config: Arc::new(ServerConfig::empty()),
                    }),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err.into())
        }
    }

    pub fn client_config(&self) -> Arc<ClientConfig> {
        Arc::new(ClientConfig::empty())
    }
}

#[derive(Clone, Debug)]
pub enum InvalidCrt {
    SubjectAltName(String),
    Verify(X509VerifyResult),
    General(Error),
}

impl From<Error> for InvalidCrt {
    fn from(err: Error) -> Self {
        InvalidCrt::General(err)
    }
}

impl From<ErrorStack> for InvalidCrt {
    fn from(err: ErrorStack) -> Self {
        InvalidCrt::General(err.into())
    }
}

impl fmt::Display for InvalidCrt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidCrt::SubjectAltName(name) => write!(f, "Subject alt name incorrect {}", name),
            InvalidCrt::Verify(err) => err.fmt(f),
            InvalidCrt::General(err) => err.fmt(f)
        }
    }
}

impl error::Error for InvalidCrt {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            InvalidCrt::Verify(err) => err.source(),
            InvalidCrt::General(err) => err.source(),
            _ => None
        }
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
    cert: X509,
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
        chain.extend(
            intermediates
                .into_iter()
                .map(|crt| X509::from_der(&crt).unwrap()),
        );

        Self { id, cert, chain, expiry }
    }

    pub fn name(&self) -> &Name {
        self.id.as_ref()
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    protocols: Arc<Vec<Vec<u8>>>,
}

impl ClientConfig {
    pub fn new(protocols: Vec<Vec<u8>>) -> Self {
        Self {
            protocols: Arc::new(protocols),
        }
    }
    pub fn empty() -> Self {
        ClientConfig::new(Vec::new())
    }

    pub fn set_protocols(&mut self, protocols: Vec<Vec<u8>>) {
        self.protocols = Arc::new(protocols)
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    alpn_protocols: Arc<Vec<Vec<u8>>>,
}

impl ServerConfig {
    pub fn new(alpn_protocols: Vec<Vec<u8>>) -> Self {
        Self {
            alpn_protocols: Arc::new(alpn_protocols),
        }
    }
    /// Produces a server config that fails to handshake all connections.
    pub fn empty() -> Self {
        ServerConfig::new(Vec::new())
    }

    pub fn add_protocols(&mut self, protocols: Vec<u8>) {
        self.alpn_protocols.as_ref().clone().push(protocols)
    }
}
