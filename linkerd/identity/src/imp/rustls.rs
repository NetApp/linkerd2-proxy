use ring::signature::EcdsaKeyPair;
use std::sync::Arc;
use std::error::Error;
use ring::rand;

pub struct SigningKey(Arc<EcdsaKeyPair>);
pub struct Signer(Arc<EcdsaKeyPair>);

#[derive(Clone, Debug)]
pub struct Key(Arc<EcdsaKeyPair>);

// These must be kept in sync:
static SIGNATURE_ALG_RING_SIGNING: &ring::signature::EcdsaSigningAlgorithm =
    &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
const SIGNATURE_ALG_RUSTLS_SCHEME: rustls::SignatureScheme =
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256;
const SIGNATURE_ALG_RUSTLS_ALGORITHM: rustls::internal::msgs::enums::SignatureAlgorithm =
    rustls::internal::msgs::enums::SignatureAlgorithm::ECDSA;
const TLS_VERSIONS: &[rustls::ProtocolVersion] = &[rustls::ProtocolVersion::TLSv1_2];

impl Key {
    pub fn from_pkcs8(b: &[u8]) -> Result<Self, dyn Error> {
        let k = EcdsaKeyPair::from_pkcs8(SIGNATURE_ALG_RING_SIGNING, b)?;
        Ok(Key(Arc::new(k)))
    }
}

impl rustls::sign::SigningKey for SigningKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&SIGNATURE_ALG_RUSTLS_SCHEME) {
            Some(Box::new(Signer(self.0.clone())))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::internal::msgs::enums::SignatureAlgorithm {
        SIGNATURE_ALG_RUSTLS_ALGORITHM
    }
}

impl rustls::sign::Signer for Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::TLSError> {
        let rng = rand::SystemRandom::new();
        self.0
            .sign(&rng, message)
            .map(|signature| signature.as_ref().to_owned())
            .map_err(|ring::error::Unspecified| {
                rustls::TLSError::General("Signing Failed".to_owned())
            })
    }

    fn get_scheme(&self) -> rustls::SignatureScheme {
        SIGNATURE_ALG_RUSTLS_SCHEME
    }
}