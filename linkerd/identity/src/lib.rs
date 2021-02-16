#![deny(warnings, rust_2018_idioms)]
use std::{convert::TryFrom, fmt, fs, io, str::FromStr, sync::Arc, time::SystemTime, error};
use tracing::{debug, warn};

#[cfg(not(feature = "fips"))]
#[path = "imp/rustls.rs"]
mod imp;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use linkerd_dns_name::InvalidName;

/// A DER-encoded X.509 certificate signing request.
#[derive(Clone, Debug)]
pub struct Csr(Arc<Vec<u8>>);

/// An error returned from the TLS implementation.
pub struct Error(imp::Error);

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        error::Error::source(&self.0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl From<imp::Error> for Error {
    fn from(err: imp::Error) -> Error {
        Error(err)
    }
}

/// An endpoint's identity.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Name(Arc<linkerd_dns_name::Name>);

#[derive(Clone, Debug)]
pub struct Key(imp::Key);

struct SigningKey(imp::SigningKey);
struct Signer(imp::Signer);

#[derive(Clone)]
pub struct TrustAnchors(imp::TrustAnchors);

#[derive(Clone, Debug)]
pub struct TokenSource(Arc<String>);

#[derive(Clone, Debug)]
pub struct Crt(imp::Crt);

#[derive(Clone)]
pub struct CrtKey(imp::CrtKey);

struct CertResolver(imp::CertResolver);

#[derive(Clone, Debug)]
pub struct InvalidCrt(imp::InvalidCrt);

/// A newtype for local server identities.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct LocalId(pub Name);

// These must be kept in sync:
static SIGNATURE_ALG_RING_SIGNING: &ring::signature::EcdsaSigningAlgorithm =
    &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
const SIGNATURE_ALG_RUSTLS_SCHEME: rustls::SignatureScheme =
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256;
const SIGNATURE_ALG_RUSTLS_ALGORITHM: rustls::internal::msgs::enums::SignatureAlgorithm =
    rustls::internal::msgs::enums::SignatureAlgorithm::ECDSA;
const TLS_VERSIONS: &[rustls::ProtocolVersion] = &[
    rustls::ProtocolVersion::TLSv1_2,
    rustls::ProtocolVersion::TLSv1_3,
];

// === impl Csr ===

impl Csr {
    pub fn from_der(der: Vec<u8>) -> Option<Self> {
        if der.is_empty() {
            return None;
        }

        Some(Csr(Arc::new(der)))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// === impl Key ===

impl Key {
    pub fn from_pkcs8(b: &[u8]) -> Result<Self, Error> {
        let key = imp::Key::from_pkcs8(b)?;
        Ok(Key(key))
    }
}

// === impl Name ===

impl From<linkerd_dns_name::Name> for Name {
    fn from(n: linkerd_dns_name::Name) -> Self {
        Name(Arc::new(n))
    }
}

impl<'t> Into<webpki::DNSNameRef<'t>> for &'t LocalId {
    fn into(self) -> webpki::DNSNameRef<'t> {
        (&self.0).into()
    }
}

impl FromStr for Name {
    type Err = InvalidName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.as_bytes().last() == Some(&b'.') {
            return Err(InvalidName); // SNI hostnames are implicitly absolute.
        }

        linkerd_dns_name::Name::from_str(s).map(|n| Name(Arc::new(n)))
    }
}

impl TryFrom<&[u8]> for Name {
    type Error = InvalidName;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        if s.last() == Some(&b'.') {
            return Err(InvalidName); // SNI hostnames are implicitly absolute.
        }

        linkerd_dns_name::Name::try_from(s).map(|n| Name(Arc::new(n)))
    }
}

impl<'t> Into<webpki::DNSNameRef<'t>> for &'t Name {
    fn into(self) -> webpki::DNSNameRef<'t> {
        self.0.as_ref().into()
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        (*self.0).as_ref()
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(&self.0, f)
    }
}

// === impl TokenSource ===

impl TokenSource {
    pub fn if_nonempty_file(p: String) -> io::Result<Self> {
        let ts = TokenSource(Arc::new(p));
        ts.load().map(|_| ts)
    }

    pub fn load(&self) -> io::Result<Vec<u8>> {
        let t = fs::read(self.0.as_str())?;

        if t.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "token is empty"));
        }

        Ok(t)
    }
}

// === impl TrustAnchors ===

impl TrustAnchors {
    #[cfg(any(test, feature = "test-util"))]
    fn empty() -> Self {
        TrustAnchors(imp::TrustAnchors::empty())
    }

    pub fn from_pem(s: &str) -> Option<TrustAnchors> {
        match imp::TrustAnchors::from_pem(s) {
            None => None,
            Some(ta) => TrustAnchors(ta)
        }
    }

    pub fn certify(&self, key: Key, crt: Crt) -> Result<CrtKey, InvalidCrt> {
        let key = self.0.certify(key.0, crt.0)?;
        Ok(CrtKey(key))
    }

    pub fn client_config(&self) -> Arc<rustls::ClientConfig> {
        self.0.client_config()
    }
}

impl fmt::Debug for TrustAnchors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustAnchors").finish()
    }
}

// === Crt ===

impl Crt {
    pub fn new(
        id: LocalId,
        leaf: Vec<u8>,
        intermediates: Vec<Vec<u8>>,
        expiry: SystemTime,
    ) -> Self {
        Self(imp::Crt::new(id, leaf, intermediates, expiry))
    }

    pub fn name(&self) -> &Name {
        self.0.name()
    }
}

impl Into<LocalId> for &'_ Crt {
    fn into(self) -> LocalId {
        self.id.clone()
    }
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

    pub fn client_config(&self) -> Arc<rustls::ClientConfig> {
        self.client_config.clone()
    }

    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
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

// === impl CertResolver ===

impl rustls::ResolvesClientCert for CertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<rustls::sign::CertifiedKey> {
        // The proxy's server-side doesn't send the list of acceptable issuers so
        // don't bother looking at `_acceptable_issuers`.
        self.resolve_(sigschemes)
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl CertResolver {
    fn resolve_(
        &self,
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<rustls::sign::CertifiedKey> {
        if !sigschemes.contains(&SIGNATURE_ALG_RUSTLS_SCHEME) {
            debug!("signature scheme not supported -> no certificate");
            return None;
        }
        Some(self.0.clone())
    }
}

impl rustls::ResolvesServerCert for CertResolver {
    fn resolve(&self, hello: rustls::ClientHello<'_>) -> Option<rustls::sign::CertifiedKey> {
        let server_name = if let Some(server_name) = hello.server_name() {
            server_name
        } else {
            debug!("no SNI -> no certificate");
            return None;
        };

        // Verify that our certificate is valid for the given SNI name.
        let c = (&self.0.cert)
            .first()
            .map(rustls::Certificate::as_ref)
            .unwrap_or(&[]); // An empty input will fail to parse.
        if let Err(err) =
            webpki::EndEntityCert::from(c).and_then(|c| c.verify_is_valid_for_dns_name(server_name))
        {
            debug!(
                "our certificate is not valid for the SNI name -> no certificate: {:?}",
                err
            );
            return None;
        }

        self.resolve_(hello.sigschemes())
    }
}

// === impl LocalId ===

impl From<Name> for LocalId {
    fn from(n: Name) -> Self {
        Self(n)
    }
}

impl Into<Name> for LocalId {
    fn into(self) -> Name {
        self.0
    }
}

impl AsRef<Name> for LocalId {
    fn as_ref(&self) -> &Name {
        &self.0
    }
}

impl fmt::Display for LocalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// === impl InvalidCrt ===

impl fmt::Display for InvalidCrt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl error::Error for InvalidCrt {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.0.source()
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::*;

    #[test]
    fn can_construct_client_and_server_config_from_valid_settings() {
        FOO_NS1.validate().expect("foo.ns1 must be valid");
    }

    #[test]
    fn recognize_ca_did_not_issue_cert() {
        let s = Identity {
            trust_anchors: include_bytes!("testdata/ca2.pem"),
            ..FOO_NS1
        };
        assert!(s.validate().is_err(), "ca2 should not validate foo.ns1");
    }

    #[test]
    fn recognize_cert_is_not_valid_for_identity() {
        let s = Identity {
            crt: BAR_NS1.crt,
            key: BAR_NS1.key,
            ..FOO_NS1
        };
        assert!(s.validate().is_err(), "identity should not be valid");
    }

    #[test]
    #[ignore] // XXX this doesn't fail because we don't actually check the key against the cert...
    fn recognize_private_key_is_not_valid_for_cert() {
        let s = Identity {
            key: BAR_NS1.key,
            ..FOO_NS1
        };
        assert!(s.validate().is_err(), "identity should not be valid");
    }
}
