//! Crypto backend of a build without `all-ciphersuites`: RustCrypto, accepting
//! only RFC 9420's mandatory-to-implement ciphersuite (0x0001).
//!
//! Every accepted call reaches RustCrypto with the suite's own algorithm as a
//! constant rather than the caller's value, so link-time optimisation can drop
//! the code of every algorithm the suite does not use.

use openmls::prelude::tls_codec::SecretVLBytes;
use openmls_rust_crypto::{RandError, RustCrypto};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
        HpkeKeyPair, KemOutput, SignatureScheme,
    },
};

pub(crate) const MANDATORY_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
// Literals, not `MANDATORY_CIPHERSUITE.hash_algorithm()` and friends: the
// optimiser does not fold those calls on wasm32, and the other arms then stay.
const MANDATORY_HASH: HashType = HashType::Sha2_256;
const MANDATORY_AEAD: AeadType = AeadType::Aes128Gcm;
const MANDATORY_SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ED25519;

#[derive(Default)]
pub struct MandatoryCiphersuiteCrypto {
    rust: RustCrypto,
}

impl MandatoryCiphersuiteCrypto {
    pub fn new() -> Self {
        Self::default()
    }
}

fn require_mandatory<T: PartialEq>(
    requested: T,
    mandatory: T,
    unsupported: CryptoError,
) -> Result<T, CryptoError> {
    if requested == mandatory {
        Ok(mandatory)
    } else {
        Err(unsupported)
    }
}

fn mandatory_hash(requested: HashType) -> Result<HashType, CryptoError> {
    require_mandatory(
        requested,
        MANDATORY_HASH,
        CryptoError::UnsupportedHashAlgorithm,
    )
}

fn mandatory_aead(requested: AeadType) -> Result<AeadType, CryptoError> {
    require_mandatory(
        requested,
        MANDATORY_AEAD,
        CryptoError::UnsupportedAeadAlgorithm,
    )
}

fn mandatory_signature_scheme(requested: SignatureScheme) -> Result<SignatureScheme, CryptoError> {
    require_mandatory(
        requested,
        MANDATORY_SIGNATURE_SCHEME,
        CryptoError::UnsupportedSignatureScheme,
    )
}

fn mandatory_hpke_config(requested: HpkeConfig) -> Result<HpkeConfig, CryptoError> {
    let mandatory = MANDATORY_CIPHERSUITE.hpke_config();
    let is_mandatory =
        requested.0 == mandatory.0 && requested.1 == mandatory.1 && requested.2 == mandatory.2;
    if is_mandatory {
        Ok(mandatory)
    } else {
        Err(CryptoError::UnsupportedCiphersuite)
    }
}

impl OpenMlsCrypto for MandatoryCiphersuiteCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        require_mandatory(
            ciphersuite,
            MANDATORY_CIPHERSUITE,
            CryptoError::UnsupportedCiphersuite,
        )
        .map(|_| ())
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![MANDATORY_CIPHERSUITE]
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.rust
            .hkdf_extract(mandatory_hash(hash_type)?, salt, ikm)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.rust.hmac(mandatory_hash(hash_type)?, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        self.rust
            .hkdf_expand(mandatory_hash(hash_type)?, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.rust.hash(mandatory_hash(hash_type)?, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.rust
            .aead_encrypt(mandatory_aead(alg)?, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.rust
            .aead_decrypt(mandatory_aead(alg)?, key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.rust
            .signature_key_gen(mandatory_signature_scheme(alg)?)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.rust
            .verify_signature(mandatory_signature_scheme(alg)?, data, pk, signature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.rust.sign(mandatory_signature_scheme(alg)?, data, key)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        self.rust
            .hpke_seal(mandatory_hpke_config(config)?, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.rust
            .hpke_open(mandatory_hpke_config(config)?, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        self.rust.hpke_setup_sender_and_export(
            mandatory_hpke_config(config)?,
            pk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        self.rust.hpke_setup_receiver_and_export(
            mandatory_hpke_config(config)?,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        self.rust
            .derive_hpke_keypair(mandatory_hpke_config(config)?, ikm)
    }
}

impl OpenMlsRand for MandatoryCiphersuiteCrypto {
    type Error = RandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        self.rust.random_array()
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.rust.random_vec(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_literals_are_the_mandatory_ciphersuite_ones() {
        assert_eq!(MANDATORY_HASH, MANDATORY_CIPHERSUITE.hash_algorithm());
        assert_eq!(MANDATORY_AEAD, MANDATORY_CIPHERSUITE.aead_algorithm());
        assert_eq!(
            MANDATORY_SIGNATURE_SCHEME,
            MANDATORY_CIPHERSUITE.signature_algorithm()
        );
    }

    #[test]
    fn only_the_mandatory_ciphersuite_is_supported() {
        let crypto = MandatoryCiphersuiteCrypto::new();
        assert_eq!(crypto.supported_ciphersuites(), vec![MANDATORY_CIPHERSUITE]);
        crypto
            .supports(MANDATORY_CIPHERSUITE)
            .expect("mandatory suite");
        for other in [
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        ] {
            assert_eq!(
                crypto.supports(other),
                Err(CryptoError::UnsupportedCiphersuite)
            );
        }
    }

    #[test]
    fn algorithms_outside_the_mandatory_ciphersuite_are_refused() {
        let crypto = MandatoryCiphersuiteCrypto::new();
        assert_eq!(
            crypto.hash(HashType::Sha2_384, b"data"),
            Err(CryptoError::UnsupportedHashAlgorithm)
        );
        assert_eq!(
            crypto.aead_encrypt(AeadType::ChaCha20Poly1305, &[1; 32], b"data", &[2; 12], b""),
            Err(CryptoError::UnsupportedAeadAlgorithm)
        );
        assert_eq!(
            crypto
                .signature_key_gen(SignatureScheme::ECDSA_SECP256R1_SHA256)
                .map(|_| ()),
            Err(CryptoError::UnsupportedSignatureScheme)
        );
        let p256_hpke = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.hpke_config();
        assert_eq!(
            crypto.derive_hpke_keypair(p256_hpke, &[3; 32]).map(|_| ()),
            Err(CryptoError::UnsupportedCiphersuite)
        );
    }

    #[test]
    fn mandatory_ciphersuite_full_group_lifecycle() {
        crate::test_support::full_group_lifecycle(MANDATORY_CIPHERSUITE);
    }
}
