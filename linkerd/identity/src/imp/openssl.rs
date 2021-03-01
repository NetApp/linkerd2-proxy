use crate::{LocalId, Name};
use std::sync::Arc;
use std::time::SystemTime;
use std::{error, fmt};

#[derive(Clone, Debug)]
pub struct Key(Arc<String>);

impl Key {
    pub fn from_pkcs8(_b: &[u8]) -> Result<Key, Error> {
        unimplemented!()
    }
}

pub struct Error(String);

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
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

// impl From<ring::error::KeyRejected> for Error {
//     fn from(error: ring::error::KeyRejected) -> Error {
//         Error(error)
//     }
// }

#[derive(Clone)]
pub struct TrustAnchors(Arc<String>);

impl TrustAnchors {
    #[cfg(any(test, feature = "test-util"))]
    pub fn empty() -> Self {
        unimplemented!()
    }

    pub fn from_pem(_s: &str) -> Option<Self> {
        unimplemented!()
    }

    pub fn certify(&self, _key: Key, _crt: Crt) -> Result<CrtKey, InvalidCrt> {
        unimplemented!()
    }

    pub fn client_config(&self) -> Arc<ClientConfig> {
        unimplemented!()
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
    // chain: Vec<rustls::Certificate>,
}

impl Crt {
    pub fn new(
        _id: LocalId,
        _leaf: Vec<u8>,
        _intermediates: Vec<Vec<u8>>,
        _expiry: SystemTime,
    ) -> Self {
        unimplemented!()
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
