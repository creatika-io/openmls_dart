//! Test helpers shared by the crypto backends' tests.

use crate::snapshot_storage::{SnapshotOpenMlsProvider, SnapshotStorageProvider};
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

/// The PRODUCTION provider with empty in-memory storage — the lifecycle
/// test must exercise the exact provider wiring that ships, not a copy.
fn test_provider() -> SnapshotOpenMlsProvider {
    SnapshotOpenMlsProvider::new(SnapshotStorageProvider::from_entries(vec![]))
}

fn make_identity(
    provider: &SnapshotOpenMlsProvider,
    name: &[u8],
    cs: Ciphersuite,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(name.to_vec());
    let signer = SignatureKeyPair::new(cs.signature_algorithm()).expect("signature keypair gen");
    signer.store(provider.storage()).expect("store signer");
    let cwk = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.public().into(),
    };
    (cwk, signer)
}

/// One full MLS group lifecycle on `cs`, against the production provider
/// wiring: create group → key package → add member (commit + Welcome) →
/// join → application messages in both directions.
pub(crate) fn full_group_lifecycle(cs: Ciphersuite) {
    // Captured output is replayed on failure, so the last line printed
    // names the suite whose lifecycle broke.
    println!("full_group_lifecycle: {cs:?}");

    let alice_provider = test_provider();
    let bob_provider = test_provider();

    let (alice_cwk, alice_signer) = make_identity(&alice_provider, b"alice", cs);
    let (bob_cwk, bob_signer) = make_identity(&bob_provider, b"bob", cs);

    // Alice creates the group (X-Wing HPKE keys in the leaf node).
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(cs)
        .use_ratchet_tree_extension(true)
        .build(&alice_provider, &alice_signer, alice_cwk)
        .expect("alice creates group");

    // Bob creates a key package (X-Wing HPKE init key), serialized round-trip.
    let bob_kp_bundle = KeyPackage::builder()
        .build(cs, &bob_provider, &bob_signer, bob_cwk)
        .expect("bob key package");
    let bob_kp_bytes = bob_kp_bundle
        .key_package()
        .tls_serialize_detached()
        .expect("kp serialize");

    // Alice validates and adds Bob — commit + Welcome (HPKE seal to X-Wing key).
    let bob_kp_in =
        KeyPackageIn::tls_deserialize_exact_bytes(&bob_kp_bytes).expect("kp deserialize");
    let bob_kp = bob_kp_in
        .validate(alice_provider.crypto(), ProtocolVersion::Mls10)
        .expect("kp validate");

    let (_commit, welcome_out, _group_info) = alice_group
        .add_members(&alice_provider, &alice_signer, &[bob_kp])
        .expect("alice adds bob");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("alice merges add commit");

    // Bob joins via Welcome (HPKE open with X-Wing key), serialized round-trip.
    let welcome_bytes = welcome_out
        .tls_serialize_detached()
        .expect("welcome serialize");
    let welcome_msg =
        MlsMessageIn::tls_deserialize_exact_bytes(&welcome_bytes).expect("welcome deserialize");
    let welcome = match welcome_msg.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("expected a Welcome message"),
    };
    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        None, // ratchet tree extension enabled
    )
    .expect("bob stages welcome")
    .into_group(&bob_provider)
    .expect("bob joins group");

    assert_eq!(alice_group.epoch(), bob_group.epoch());
    assert_eq!(alice_group.members().count(), 2);
    assert_eq!(bob_group.members().count(), 2);
    assert_eq!(alice_group.ciphersuite(), cs);
    assert_eq!(bob_group.ciphersuite(), cs);

    // Alice → Bob application message.
    let msg_out = alice_group
        .create_message(&alice_provider, &alice_signer, b"hello bob")
        .expect("alice creates message");
    let msg_bytes = msg_out.tls_serialize_detached().expect("msg serialize");
    let protocol_msg = MlsMessageIn::tls_deserialize_exact_bytes(&msg_bytes)
        .expect("msg deserialize")
        .try_into_protocol_message()
        .expect("protocol message");
    let processed = bob_group
        .process_message(&bob_provider, protocol_msg)
        .expect("bob processes message");
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(am) => {
            assert_eq!(am.into_bytes(), b"hello bob".to_vec());
        }
        _ => panic!("expected application message"),
    }

    // Bob → Alice application message.
    let msg_out = bob_group
        .create_message(&bob_provider, &bob_signer, b"hi alice")
        .expect("bob creates message");
    let msg_bytes = msg_out.tls_serialize_detached().expect("msg serialize");
    let protocol_msg = MlsMessageIn::tls_deserialize_exact_bytes(&msg_bytes)
        .expect("msg deserialize")
        .try_into_protocol_message()
        .expect("protocol message");
    let processed = alice_group
        .process_message(&alice_provider, protocol_msg)
        .expect("alice processes message");
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(am) => {
            assert_eq!(am.into_bytes(), b"hi alice".to_vec());
        }
        _ => panic!("expected application message"),
    }
}
