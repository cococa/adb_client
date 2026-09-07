//! Android 11+ wireless-debugging pairing.
//!
//! The SPAKE2 math in this module follows the BoringSSL variant used by AOSP
//! ADB rather than RFC 9382. Portions were adapted from DroidMux's pairing
//! implementation, available under Apache-2.0 OR MIT; see THIRD_PARTY_NOTICES.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    sync::Arc,
    time::Duration,
};

use aes_gcm::{
    Aes128Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use hkdf::Hkdf;
use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256, Sha512};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroizing;

use crate::{ADBRsaKey, Result, RustADBError, read_adb_private_key};

const CLIENT_NAME: &[u8] = b"adb pair client\0";
const SERVER_NAME: &[u8] = b"adb pair server\0";
const TLS_EXPORTER_LABEL: &[u8] = b"adb-label\0";
const AES_INFO: &[u8] = b"adb pairing_auth aes-128-gcm key";
const PEER_INFO_SIZE: usize = 8192;
const MAX_PAIRING_PAYLOAD: usize = PEER_INFO_SIZE * 2;
const SPAKE_M: [u8; 32] = [
    0x5a, 0xda, 0x7e, 0x4b, 0xf6, 0xdd, 0xd9, 0xad, 0xb6, 0x62, 0x6d, 0x32, 0x13, 0x1c, 0x6b, 0x5c,
    0x51, 0xa1, 0xe3, 0x47, 0xa3, 0x47, 0x8f, 0x53, 0xcf, 0xcf, 0x44, 0x1b, 0x88, 0xee, 0xd1, 0x2e,
];
const SPAKE_N: [u8; 32] = [
    0x10, 0xe3, 0xdf, 0x0a, 0xe3, 0x7d, 0x8e, 0x7a, 0x99, 0xb5, 0xfe, 0x74, 0xb4, 0x46, 0x72, 0x10,
    0x3d, 0xbd, 0xdc, 0xbd, 0x06, 0xaf, 0x68, 0x0d, 0x71, 0x32, 0x9a, 0x11, 0x69, 0x3b, 0xc7, 0x78,
];
const GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Pairs the host key with an Android wireless-debugging pairing endpoint.
/// Returns the stable Android pairing GUID on success.
pub fn pair(address: SocketAddr, pairing_code: &str, key_path: &Path) -> Result<String> {
    if pairing_code.len() != 6 || !pairing_code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(failure("pairing code must contain exactly six digits"));
    }
    let key = load_or_create_key(key_path)?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut tls = connect_tls(stream, &key, address)?;
    let mut exporter = [0_u8; 64];
    tls.conn
        .export_keying_material(&mut exporter, TLS_EXPORTER_LABEL, None)?;
    let mut password = Zeroizing::new(Vec::with_capacity(pairing_code.len() + exporter.len()));
    password.extend_from_slice(pairing_code.as_bytes());
    password.extend_from_slice(&exporter);

    let (spake, message) = SpakeState::start(&password)?;
    write_packet(&mut tls, 0, &message)?;
    let peer_message = read_packet(&mut tls, 0)?;
    let key_material = spake.finish(&peer_message)?;
    let mut cipher = PairingCipher::new(key_material.as_slice())?;

    let public_key = key.android_pubkey_encode()?;
    let mut peer_info = [0_u8; PEER_INFO_SIZE];
    let public_key = public_key.as_bytes();
    if public_key.len() >= PEER_INFO_SIZE {
        return Err(failure("ADB public key is too large for pairing"));
    }
    peer_info[1..=public_key.len()].copy_from_slice(public_key);
    write_packet(&mut tls, 1, &cipher.encrypt(&peer_info)?)?;
    let device_info = cipher.decrypt(&read_packet(&mut tls, 1)?)?;
    parse_device_guid(&device_info)
}

fn load_or_create_key(path: &Path) -> Result<ADBRsaKey> {
    if let Some(key) = read_adb_private_key(path)? {
        return Ok(key);
    }
    let key = ADBRsaKey::new_random()?;
    key.write_pkcs8(path)?;
    Ok(key)
}

fn connect_tls(
    stream: TcpStream,
    key: &ADBRsaKey,
    address: SocketAddr,
) -> Result<StreamOwned<ClientConnection, TcpStream>> {
    let pem = key.to_pkcs8_pem()?;
    let key_pair = KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &PKCS_RSA_SHA256)?;
    let certificate = CertificateParams::default()
        .self_signed(&key_pair)?
        .der()
        .to_owned();
    let private_key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
        .with_client_auth_cert(vec![certificate], private_key.into())?;
    let server_name = ServerName::IpAddress(address.ip().into());
    let connection = ClientConnection::new(Arc::new(config), server_name)?;
    let mut tls = StreamOwned::new(connection, stream);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(tls)
}

fn write_packet(stream: &mut impl Write, kind: u8, payload: &[u8]) -> Result<()> {
    if payload.is_empty() || payload.len() > MAX_PAIRING_PAYLOAD {
        return Err(failure("invalid pairing payload length"));
    }
    let length = u32::try_from(payload.len()).map_err(|_| failure("pairing payload too large"))?;
    stream.write_all(&[1, kind])?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn read_packet(stream: &mut impl Read, expected_kind: u8) -> Result<Vec<u8>> {
    let mut header = [0_u8; 6];
    stream.read_exact(&mut header)?;
    if header[0] != 1 || header[1] != expected_kind {
        return Err(failure("unexpected wireless pairing packet"));
    }
    let length = usize::try_from(u32::from_be_bytes(
        header[2..]
            .try_into()
            .map_err(|_| failure("invalid pairing header"))?,
    ))
    .map_err(|_| failure("pairing payload overflow"))?;
    if length == 0 || length > MAX_PAIRING_PAYLOAD {
        return Err(failure("invalid pairing payload length"));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn parse_device_guid(value: &[u8]) -> Result<String> {
    if value.len() != PEER_INFO_SIZE || value[0] != 1 {
        return Err(failure("pairing code was rejected"));
    }
    let body = &value[1..];
    let Some(end) = body.iter().position(|byte| *byte == 0) else {
        return Err(failure("invalid Android pairing identifier"));
    };
    let guid = std::str::from_utf8(&body[..end])?.to_owned();
    if guid.is_empty() || guid.len() > 255 || guid.chars().any(char::is_control) {
        return Err(failure("invalid Android pairing identifier"));
    }
    Ok(guid)
}

fn failure(message: impl Into<String>) -> RustADBError {
    RustADBError::ADBRequestFailed(message.into())
}

struct SpakeState {
    private_scalar: Zeroizing<[u8; 32]>,
    password_scalar: Zeroizing<[u8; 32]>,
    password_hash: Zeroizing<[u8; 64]>,
    message: [u8; 32],
}

impl SpakeState {
    fn start(password: &[u8]) -> Result<(Self, [u8; 32])> {
        let random: [u8; 64] = rand::random();
        let mut private_scalar = Scalar::from_bytes_mod_order_wide(&random).to_bytes();
        shift_left_three(&mut private_scalar);
        let password_hash: [u8; 64] = Sha512::digest(password).into();
        let mut password_scalar = Scalar::from_bytes_mod_order_wide(&password_hash).to_bytes();
        clear_cofactor_bits(&mut password_scalar);
        let mask = decode_point(SPAKE_M)?;
        let public = multiply_raw(&ED25519_BASEPOINT_POINT, &private_scalar);
        let message = (public + multiply_raw(&mask, &password_scalar))
            .compress()
            .to_bytes();
        Ok((
            Self {
                private_scalar: Zeroizing::new(private_scalar),
                password_scalar: Zeroizing::new(password_scalar),
                password_hash: Zeroizing::new(password_hash),
                message,
            },
            message,
        ))
    }

    fn finish(self, peer_message: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
        let peer: [u8; 32] = peer_message
            .try_into()
            .map_err(|_| failure("invalid SPAKE2 message length"))?;
        let peer_masked = decode_point(peer)?;
        let peer_public =
            peer_masked - multiply_raw(&decode_point(SPAKE_N)?, &self.password_scalar);
        let shared = multiply_raw(&peer_public, &self.private_scalar)
            .compress()
            .to_bytes();
        let mut transcript = Sha512::new();
        for value in [
            CLIENT_NAME,
            SERVER_NAME,
            self.message.as_slice(),
            peer_message,
            shared.as_slice(),
            self.password_hash.as_slice(),
        ] {
            transcript.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
            transcript.update(value);
        }
        Ok(Zeroizing::new(transcript.finalize().into()))
    }
}

struct PairingCipher {
    cipher: Aes128Gcm,
    encrypt_sequence: u64,
    decrypt_sequence: u64,
}

impl PairingCipher {
    fn new(material: &[u8]) -> Result<Self> {
        let mut key = [0_u8; 16];
        Hkdf::<Sha256>::new(None, material)
            .expand(AES_INFO, &mut key)
            .map_err(|_| failure("cannot derive pairing cipher"))?;
        Ok(Self {
            cipher: Aes128Gcm::new((&key).into()),
            encrypt_sequence: 0,
            decrypt_sequence: 0,
        })
    }
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce(self.encrypt_sequence);
        self.encrypt_sequence = self
            .encrypt_sequence
            .checked_add(1)
            .ok_or_else(|| failure("pairing nonce exhausted"))?;
        self.cipher
            .encrypt(Nonce::from_slice(&nonce), Payload::from(plaintext))
            .map_err(|_| failure("cannot encrypt pairing information"))
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce(self.decrypt_sequence);
        self.decrypt_sequence = self
            .decrypt_sequence
            .checked_add(1)
            .ok_or_else(|| failure("pairing nonce exhausted"))?;
        self.cipher
            .decrypt(Nonce::from_slice(&nonce), Payload::from(ciphertext))
            .map_err(|_| failure("pairing code was rejected"))
    }
}

fn decode_point(value: [u8; 32]) -> Result<EdwardsPoint> {
    CompressedEdwardsY(value)
        .decompress()
        .ok_or_else(|| failure("invalid SPAKE2 point"))
}
fn multiply_raw(point: &EdwardsPoint, scalar: &[u8; 32]) -> EdwardsPoint {
    let mut result = EdwardsPoint::identity();
    let mut multiple = *point;
    for byte in scalar {
        for bit in 0..8 {
            let candidate = result + multiple;
            result = EdwardsPoint::conditional_select(
                &result,
                &candidate,
                Choice::from((byte >> bit) & 1),
            );
            multiple = multiple + multiple;
        }
    }
    result
}
fn shift_left_three(value: &mut [u8; 32]) {
    let mut carry = 0;
    for byte in value {
        let next = *byte >> 5;
        *byte = (*byte << 3) | carry;
        carry = next;
    }
}
fn clear_cofactor_bits(value: &mut [u8; 32]) {
    let mut order = GROUP_ORDER;
    for bit in 0..3 {
        let sum = add_le(value, &order);
        let choice = Choice::from((value[0] >> bit) & 1);
        for (output, candidate) in value.iter_mut().zip(sum) {
            *output = u8::conditional_select(output, &candidate, choice);
        }
        order = add_le(&order, &order);
    }
}
fn add_le(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    let mut carry = 0_u16;
    for index in 0..32 {
        let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
    }
    output
}
fn nonce(sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..8].copy_from_slice(&sequence.to_le_bytes());
    nonce
}

#[derive(Debug)]
struct AcceptAnyCertificate;
impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}
