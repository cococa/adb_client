//! Byte-for-byte compatibility with the existing blocking `adb_client`.

use adb_client::ADBRsaKey;
use adb_proto::auth::AdbKey;

// Same fixture key as adb_client's adb_rsa_key tests.
const TEST_KEY: &str = include_str!("fixtures/test_key.pem");

#[test]
fn token_signature_matches_adb_client() {
    let token = [0x5Au8; 20];
    let ours = AdbKey::from_pkcs8_pem(TEST_KEY).unwrap().sign_token(&token).unwrap();
    let theirs = ADBRsaKey::new_from_pkcs8(TEST_KEY).unwrap().sign(token).unwrap();
    assert_eq!(ours, theirs);
}

#[test]
fn public_key_matches_adb_client() {
    let ours = AdbKey::from_pkcs8_pem(TEST_KEY)
        .unwrap()
        .android_public_key("andro-connect")
        .unwrap();
    let theirs = ADBRsaKey::new_from_pkcs8(TEST_KEY)
        .unwrap()
        .android_pubkey_encode()
        .unwrap();
    let ours = String::from_utf8(ours).unwrap();
    assert_eq!(ours.split(' ').next(), theirs.split(' ').next());
    assert!(ours.ends_with(" andro-connect\0"));
}

#[test]
fn pem_round_trip_keeps_signatures() {
    let key = AdbKey::from_pkcs8_pem(TEST_KEY).unwrap();
    let reloaded = AdbKey::from_pkcs8_pem(&key.to_pkcs8_pem().unwrap()).unwrap();
    // adbd tokens are always 20 bytes, the SHA-1 digest size.
    let token = [7u8; 20];
    assert_eq!(key.sign_token(&token).unwrap(), reloaded.sign_token(&token).unwrap());
}
