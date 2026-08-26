//! Versioned, fixed-size onion cells for the Peerless anonymous data plane.
//!
//! This crate provides cryptographic wire primitives only. Route selection and
//! network transport live above it. No persistent peer identity, membership
//! certificate, public key, or address is represented by these wire types.

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, ReusableSecret, StaticSecret};
use zeroize::Zeroizing;

pub const PROTOCOL_VERSION: u16 = 1;
pub const SETUP_REQUEST_SIZE: usize = 128;
pub const SETUP_RESPONSE_SIZE: usize = 160;
pub const CELL_SIZE: usize = 1024;
pub const MAX_HOPS: usize = 3;
pub const MAX_FRAGMENT_COUNT: u32 = 1024;
pub const MAX_MESSAGE_SIZE: usize = 512 * 1024;

const SETUP_MAGIC: &[u8; 4] = b"PLS1";
const RESPONSE_MAGIC: &[u8; 4] = b"PLR1";
const CELL_MAGIC: &[u8; 4] = b"PLC1";
const SETUP_FIELDS_SIZE: usize = 104;
const RESPONSE_FIELDS_SIZE: usize = 152;
const CELL_HEADER_SIZE: usize = 50;
const TAG_SIZE: usize = 16;
const LAYER_HEADER_SIZE: usize = 3;
const MAX_LAYER_DATA: usize = CELL_SIZE - CELL_HEADER_SIZE - TAG_SIZE - LAYER_HEADER_SIZE;
const MAX_FUTURE_SEQUENCE_JUMP: u64 = 64;
const REPLAY_WINDOW_BITS: u64 = 128;
const MAX_INFLIGHT_MESSAGES: usize = 16;
const FRAGMENT_HEADER_SIZE: usize = 16 + 4 + 4 + 4;

pub fn max_payload_for_hops(hops: usize) -> Result<usize, OnionError> {
    if hops == 0 || hops > MAX_HOPS {
        return Err(OnionError::HopLimit);
    }
    let layer_overhead = CELL_HEADER_SIZE + TAG_SIZE + LAYER_HEADER_SIZE;
    MAX_LAYER_DATA
        .checked_sub((hops - 1) * layer_overhead)
        .ok_or(OnionError::PayloadTooLarge)
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum OnionError {
    #[error("onion protocol version is unsupported")]
    UnsupportedVersion,
    #[error("onion message encoding is invalid")]
    InvalidEncoding,
    #[error("onion setup or cell is expired")]
    Expired,
    #[error("onion setup transcript does not match")]
    TranscriptMismatch,
    #[error("onion key agreement failed")]
    KeyAgreementFailed,
    #[error("onion cell authentication failed")]
    AuthenticationFailed,
    #[error("onion cell scope does not match this hop")]
    WrongScope,
    #[error("onion cell was replayed or duplicated")]
    Replay,
    #[error("onion cell sequence is outside the bounded window")]
    OutOfWindow,
    #[error("onion route exceeds the supported hop bound")]
    HopLimit,
    #[error("onion payload exceeds its strict bound")]
    PayloadTooLarge,
    #[error("fragment state exceeds its strict bound")]
    FragmentCapacity,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Direction {
    Forward = 1,
    Reverse = 2,
}

impl TryFrom<u8> for Direction {
    type Error = OnionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Forward),
            2 => Ok(Self::Reverse),
            _ => Err(OnionError::InvalidEncoding),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CellType {
    Setup = 1,
    Data = 2,
    Padding = 3,
    Response = 4,
    Rotation = 5,
    Teardown = 6,
}

impl TryFrom<u8> for CellType {
    type Error = OnionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Setup),
            2 => Ok(Self::Data),
            3 => Ok(Self::Padding),
            4 => Ok(Self::Response),
            5 => Ok(Self::Rotation),
            6 => Ok(Self::Teardown),
            _ => Err(OnionError::InvalidEncoding),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupContext {
    pub circuit_id: [u8; 16],
    pub hop: u8,
    pub epoch: u64,
    pub expires_at: u64,
}

impl SetupContext {
    fn validate(&self, now: u64) -> Result<(), OnionError> {
        if self.hop >= MAX_HOPS as u8 || self.expires_at <= now {
            return Err(if self.expires_at <= now {
                OnionError::Expired
            } else {
                OnionError::HopLimit
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupRequest([u8; SETUP_REQUEST_SIZE]);

impl SetupRequest {
    pub fn as_bytes(&self) -> &[u8; SETUP_REQUEST_SIZE] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnionError> {
        let value: [u8; SETUP_REQUEST_SIZE] =
            bytes.try_into().map_err(|_| OnionError::InvalidEncoding)?;
        parse_setup_request(&value)?;
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupResponse([u8; SETUP_RESPONSE_SIZE]);

impl SetupResponse {
    pub fn as_bytes(&self) -> &[u8; SETUP_RESPONSE_SIZE] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnionError> {
        let value: [u8; SETUP_RESPONSE_SIZE] =
            bytes.try_into().map_err(|_| OnionError::InvalidEncoding)?;
        parse_setup_response(&value)?;
        Ok(Self(value))
    }
}

pub struct PendingSetup {
    context: SetupContext,
    secret: ReusableSecret,
    initiator_public: [u8; 32],
    relay_public: [u8; 32],
}

impl std::fmt::Debug for PendingSetup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingSetup")
            .field("context", &self.context)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

pub struct HopKeys {
    circuit_id: [u8; 16],
    hop: u8,
    epoch: u64,
    expires_at: u64,
    forward_key: Zeroizing<[u8; 32]>,
    reverse_key: Zeroizing<[u8; 32]>,
    forward_nonce_prefix: [u8; 4],
    reverse_nonce_prefix: [u8; 4],
}

impl std::fmt::Debug for HopKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HopKeys")
            .field("circuit_id", &self.circuit_id)
            .field("hop", &self.hop)
            .field("epoch", &self.epoch)
            .field("expires_at", &self.expires_at)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl HopKeys {
    pub fn circuit_id(&self) -> [u8; 16] {
        self.circuit_id
    }

    pub fn hop(&self) -> u8 {
        self.hop
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    fn key_and_nonce(&self, direction: Direction, sequence: u64) -> (&[u8; 32], [u8; 12]) {
        let (key, prefix) = match direction {
            Direction::Forward => (&*self.forward_key, self.forward_nonce_prefix),
            Direction::Reverse => (&*self.reverse_key, self.reverse_nonce_prefix),
        };
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&prefix);
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        (key, nonce)
    }
}

pub struct InitiatorSetup;

/// Runtime-generated relay service key. Its public half is intended for a
/// governance-signed relay descriptor; the secret half never enters a cell.
pub struct RelayOnionSecret(StaticSecret);

impl RelayOnionSecret {
    pub fn generate() -> Self {
        Self(StaticSecret::random())
    }

    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }
}

impl std::fmt::Debug for RelayOnionSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("RelayOnionSecret")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl InitiatorSetup {
    pub fn start(
        context: SetupContext,
        relay_public: [u8; 32],
        now: u64,
    ) -> Result<(SetupRequest, PendingSetup), OnionError> {
        context.validate(now)?;
        let secret = ReusableSecret::random();
        let initiator_public = PublicKey::from(&secret).to_bytes();
        let request = SetupRequest(encode_setup_request(
            context,
            initiator_public,
            relay_public,
        ));
        Ok((
            request,
            PendingSetup {
                context,
                secret,
                initiator_public,
                relay_public,
            },
        ))
    }

    pub fn finish(
        pending: PendingSetup,
        response: &SetupResponse,
        now: u64,
    ) -> Result<HopKeys, OnionError> {
        let parsed = parse_setup_response(&response.0)?;
        pending.context.validate(now)?;
        if parsed.context != pending.context
            || parsed.initiator_public != pending.initiator_public
            || parsed.relay_public != pending.relay_public
        {
            return Err(OnionError::TranscriptMismatch);
        }
        let static_shared = pending
            .secret
            .diffie_hellman(&PublicKey::from(parsed.relay_public));
        let ephemeral_shared = pending
            .secret
            .diffie_hellman(&PublicKey::from(parsed.responder_public));
        if !static_shared.was_contributory() || !ephemeral_shared.was_contributory() {
            return Err(OnionError::KeyAgreementFailed);
        }
        let transcript = setup_transcript(
            pending.context,
            pending.initiator_public,
            parsed.responder_public,
            parsed.relay_public,
        );
        let mut shared = Zeroizing::new([0u8; 64]);
        shared[..32].copy_from_slice(static_shared.as_bytes());
        shared[32..].copy_from_slice(ephemeral_shared.as_bytes());
        let (keys, confirmation_key) = derive_keys(&shared[..], &transcript, pending.context)?;
        let expected = confirmation_tag(&confirmation_key, &transcript)?;
        if expected != parsed.confirmation {
            return Err(OnionError::TranscriptMismatch);
        }
        Ok(keys)
    }
}

pub struct RelaySetup;

impl RelaySetup {
    pub fn accept(
        request: &SetupRequest,
        relay_secret: &RelayOnionSecret,
        now: u64,
    ) -> Result<(SetupResponse, HopKeys), OnionError> {
        let parsed = parse_setup_request(&request.0)?;
        parsed.context.validate(now)?;
        if parsed.relay_public != relay_secret.public_key() {
            return Err(OnionError::WrongScope);
        }
        let secret = EphemeralSecret::random();
        let responder_public = PublicKey::from(&secret).to_bytes();
        let initiator_public = PublicKey::from(parsed.initiator_public);
        let static_shared = relay_secret.0.diffie_hellman(&initiator_public);
        let ephemeral_shared = secret.diffie_hellman(&initiator_public);
        if !static_shared.was_contributory() || !ephemeral_shared.was_contributory() {
            return Err(OnionError::KeyAgreementFailed);
        }
        let transcript = setup_transcript(
            parsed.context,
            parsed.initiator_public,
            responder_public,
            parsed.relay_public,
        );
        let mut shared = Zeroizing::new([0u8; 64]);
        shared[..32].copy_from_slice(static_shared.as_bytes());
        shared[32..].copy_from_slice(ephemeral_shared.as_bytes());
        let (keys, confirmation_key) = derive_keys(&shared[..], &transcript, parsed.context)?;
        let confirmation = confirmation_tag(&confirmation_key, &transcript)?;
        Ok((
            SetupResponse(encode_setup_response(
                parsed.context,
                parsed.initiator_public,
                responder_public,
                parsed.relay_public,
                confirmation,
            )),
            keys,
        ))
    }
}

#[derive(Clone, Copy)]
struct ParsedSetupRequest {
    context: SetupContext,
    initiator_public: [u8; 32],
    relay_public: [u8; 32],
}

#[derive(Clone, Copy)]
struct ParsedSetupResponse {
    context: SetupContext,
    initiator_public: [u8; 32],
    responder_public: [u8; 32],
    relay_public: [u8; 32],
    confirmation: [u8; 16],
}

fn encode_setup_request(
    context: SetupContext,
    initiator_public: [u8; 32],
    relay_public: [u8; 32],
) -> [u8; SETUP_REQUEST_SIZE] {
    let mut bytes = [0u8; SETUP_REQUEST_SIZE];
    bytes[..4].copy_from_slice(SETUP_MAGIC);
    bytes[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    bytes[6] = context.hop;
    bytes[8..24].copy_from_slice(&context.circuit_id);
    bytes[24..32].copy_from_slice(&context.epoch.to_be_bytes());
    bytes[32..40].copy_from_slice(&context.expires_at.to_be_bytes());
    bytes[40..72].copy_from_slice(&initiator_public);
    bytes[72..104].copy_from_slice(&relay_public);
    bytes
}

fn parse_setup_request(bytes: &[u8; SETUP_REQUEST_SIZE]) -> Result<ParsedSetupRequest, OnionError> {
    if &bytes[..4] != SETUP_MAGIC
        || bytes[7] != 0
        || bytes[SETUP_FIELDS_SIZE..].iter().any(|byte| *byte != 0)
    {
        return Err(OnionError::InvalidEncoding);
    }
    if u16::from_be_bytes([bytes[4], bytes[5]]) != PROTOCOL_VERSION {
        return Err(OnionError::UnsupportedVersion);
    }
    Ok(ParsedSetupRequest {
        context: SetupContext {
            circuit_id: bytes[8..24].try_into().expect("fixed circuit slice"),
            hop: bytes[6],
            epoch: u64::from_be_bytes(bytes[24..32].try_into().expect("fixed epoch slice")),
            expires_at: u64::from_be_bytes(bytes[32..40].try_into().expect("fixed expiry slice")),
        },
        initiator_public: bytes[40..72].try_into().expect("fixed public-key slice"),
        relay_public: bytes[72..104].try_into().expect("fixed relay-key slice"),
    })
}

fn encode_setup_response(
    context: SetupContext,
    initiator_public: [u8; 32],
    responder_public: [u8; 32],
    relay_public: [u8; 32],
    confirmation: [u8; 16],
) -> [u8; SETUP_RESPONSE_SIZE] {
    let mut bytes = [0u8; SETUP_RESPONSE_SIZE];
    bytes[..4].copy_from_slice(RESPONSE_MAGIC);
    bytes[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    bytes[6] = context.hop;
    bytes[8..24].copy_from_slice(&context.circuit_id);
    bytes[24..32].copy_from_slice(&context.epoch.to_be_bytes());
    bytes[32..40].copy_from_slice(&context.expires_at.to_be_bytes());
    bytes[40..72].copy_from_slice(&initiator_public);
    bytes[72..104].copy_from_slice(&responder_public);
    bytes[104..136].copy_from_slice(&relay_public);
    bytes[136..152].copy_from_slice(&confirmation);
    bytes
}

fn parse_setup_response(
    bytes: &[u8; SETUP_RESPONSE_SIZE],
) -> Result<ParsedSetupResponse, OnionError> {
    if &bytes[..4] != RESPONSE_MAGIC
        || bytes[7] != 0
        || bytes[RESPONSE_FIELDS_SIZE..].iter().any(|byte| *byte != 0)
    {
        return Err(OnionError::InvalidEncoding);
    }
    if u16::from_be_bytes([bytes[4], bytes[5]]) != PROTOCOL_VERSION {
        return Err(OnionError::UnsupportedVersion);
    }
    Ok(ParsedSetupResponse {
        context: SetupContext {
            circuit_id: bytes[8..24].try_into().expect("fixed circuit slice"),
            hop: bytes[6],
            epoch: u64::from_be_bytes(bytes[24..32].try_into().expect("fixed epoch slice")),
            expires_at: u64::from_be_bytes(bytes[32..40].try_into().expect("fixed expiry slice")),
        },
        initiator_public: bytes[40..72].try_into().expect("fixed public-key slice"),
        responder_public: bytes[72..104].try_into().expect("fixed public-key slice"),
        relay_public: bytes[104..136].try_into().expect("fixed relay-key slice"),
        confirmation: bytes[136..152]
            .try_into()
            .expect("fixed confirmation slice"),
    })
}

fn setup_transcript(
    context: SetupContext,
    initiator_public: [u8; 32],
    responder_public: [u8; 32],
    relay_public: [u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(147);
    transcript.extend_from_slice(b"peerless/onion/setup/v1");
    transcript.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    transcript.extend_from_slice(&context.circuit_id);
    transcript.push(context.hop);
    transcript.extend_from_slice(&context.epoch.to_be_bytes());
    transcript.extend_from_slice(&context.expires_at.to_be_bytes());
    transcript.extend_from_slice(&initiator_public);
    transcript.extend_from_slice(&responder_public);
    transcript.extend_from_slice(&relay_public);
    transcript
}

fn derive_keys(
    shared: &[u8],
    transcript: &[u8],
    context: SetupContext,
) -> Result<(HopKeys, Zeroizing<[u8; 32]>), OnionError> {
    let salt = Sha256::digest(transcript);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut output = Zeroizing::new([0u8; 104]);
    hkdf.expand(b"peerless/onion/hop-keys/v1", &mut *output)
        .map_err(|_| OnionError::KeyAgreementFailed)?;
    let forward_key = Zeroizing::new(output[..32].try_into().expect("fixed key slice"));
    let reverse_key = Zeroizing::new(output[32..64].try_into().expect("fixed key slice"));
    let forward_nonce_prefix = output[64..68].try_into().expect("fixed nonce slice");
    let reverse_nonce_prefix = output[68..72].try_into().expect("fixed nonce slice");
    let confirmation_key = Zeroizing::new(output[72..104].try_into().expect("fixed key slice"));
    Ok((
        HopKeys {
            circuit_id: context.circuit_id,
            hop: context.hop,
            epoch: context.epoch,
            expires_at: context.expires_at,
            forward_key,
            reverse_key,
            forward_nonce_prefix,
            reverse_nonce_prefix,
        },
        confirmation_key,
    ))
}

fn confirmation_tag(key: &[u8; 32], transcript: &[u8]) -> Result<[u8; 16], OnionError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&[0u8; 12]), transcript, &mut [])
        .map_err(|_| OnionError::AuthenticationFailed)?;
    Ok(tag.into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireCell([u8; CELL_SIZE]);

impl WireCell {
    pub fn as_bytes(&self) -> &[u8; CELL_SIZE] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnionError> {
        let value: [u8; CELL_SIZE] = bytes.try_into().map_err(|_| OnionError::InvalidEncoding)?;
        parse_cell_header(&value)?;
        Ok(Self(value))
    }

    fn from_compact(compact: &[u8]) -> Result<Self, OnionError> {
        if compact.len() > CELL_SIZE
            || compact.len() < CELL_HEADER_SIZE + TAG_SIZE + LAYER_HEADER_SIZE
        {
            return Err(OnionError::InvalidEncoding);
        }
        let mut bytes = [0u8; CELL_SIZE];
        bytes[..compact.len()].copy_from_slice(compact);
        parse_cell_header(&bytes)?;
        Ok(Self(bytes))
    }

    fn compact(&self) -> Result<&[u8], OnionError> {
        let header = parse_cell_header(&self.0)?;
        Ok(&self.0[..CELL_HEADER_SIZE + header.ciphertext_len])
    }
}

#[derive(Clone, Copy, Debug)]
struct CellHeader {
    direction: Direction,
    circuit_id: [u8; 16],
    epoch: u64,
    expires_at: u64,
    sequence: u64,
    ciphertext_len: usize,
}

fn encode_cell_header(
    keys: &HopKeys,
    direction: Direction,
    sequence: u64,
    ciphertext_len: usize,
) -> [u8; CELL_HEADER_SIZE] {
    let mut header = [0u8; CELL_HEADER_SIZE];
    header[..4].copy_from_slice(CELL_MAGIC);
    header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    header[6] = 1; // Generic onion layer; the inner cell type remains encrypted.
    header[7] = direction as u8;
    header[8..24].copy_from_slice(&keys.circuit_id);
    header[24..32].copy_from_slice(&keys.epoch.to_be_bytes());
    header[32..40].copy_from_slice(&keys.expires_at.to_be_bytes());
    header[40..48].copy_from_slice(&sequence.to_be_bytes());
    header[48..50].copy_from_slice(&(ciphertext_len as u16).to_be_bytes());
    header
}

fn parse_cell_header(bytes: &[u8; CELL_SIZE]) -> Result<CellHeader, OnionError> {
    if &bytes[..4] != CELL_MAGIC || bytes[6] != 1 {
        return Err(OnionError::InvalidEncoding);
    }
    if u16::from_be_bytes([bytes[4], bytes[5]]) != PROTOCOL_VERSION {
        return Err(OnionError::UnsupportedVersion);
    }
    let ciphertext_len = u16::from_be_bytes([bytes[48], bytes[49]]) as usize;
    let compact_len = CELL_HEADER_SIZE
        .checked_add(ciphertext_len)
        .ok_or(OnionError::InvalidEncoding)?;
    if ciphertext_len < TAG_SIZE + LAYER_HEADER_SIZE
        || compact_len > CELL_SIZE
        || bytes[compact_len..].iter().any(|byte| *byte != 0)
    {
        return Err(OnionError::InvalidEncoding);
    }
    Ok(CellHeader {
        direction: Direction::try_from(bytes[7])?,
        circuit_id: bytes[8..24].try_into().expect("fixed circuit slice"),
        epoch: u64::from_be_bytes(bytes[24..32].try_into().expect("fixed epoch slice")),
        expires_at: u64::from_be_bytes(bytes[32..40].try_into().expect("fixed expiry slice")),
        sequence: u64::from_be_bytes(bytes[40..48].try_into().expect("fixed sequence slice")),
        ciphertext_len,
    })
}

fn seal_compact(
    keys: &HopKeys,
    direction: Direction,
    sequence: u64,
    layer_type: u8,
    data: &[u8],
) -> Result<Vec<u8>, OnionError> {
    if data.len() > MAX_LAYER_DATA {
        return Err(OnionError::PayloadTooLarge);
    }
    let mut plaintext = Vec::with_capacity(LAYER_HEADER_SIZE + data.len());
    plaintext.push(layer_type);
    plaintext.extend_from_slice(&(data.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(data);
    let ciphertext_len = plaintext.len() + TAG_SIZE;
    let header = encode_cell_header(keys, direction, sequence, ciphertext_len);
    let compact_len = CELL_HEADER_SIZE + ciphertext_len;
    let padding = vec![0u8; CELL_SIZE - compact_len];
    let mut aad = Vec::with_capacity(CELL_HEADER_SIZE + padding.len());
    aad.extend_from_slice(&header);
    aad.extend_from_slice(&padding);
    let (key, nonce) = keys.key_and_nonce(direction, sequence);
    let cipher = ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut plaintext)
        .map_err(|_| OnionError::AuthenticationFailed)?;
    let mut compact = Vec::with_capacity(compact_len);
    compact.extend_from_slice(&header);
    compact.extend_from_slice(&plaintext);
    compact.extend_from_slice(&tag);
    Ok(compact)
}

pub struct CircuitSender {
    traversal_keys: Vec<HopKeys>,
    direction: Direction,
    next_sequence: u64,
}

impl CircuitSender {
    /// Owns all hop keys in traversal order and assigns every AEAD nonce
    /// monotonically. For a reverse path, pass keys in reverse traversal order.
    pub fn new(traversal_keys: Vec<HopKeys>, direction: Direction) -> Result<Self, OnionError> {
        if traversal_keys.is_empty() || traversal_keys.len() > MAX_HOPS {
            return Err(OnionError::HopLimit);
        }
        let first = &traversal_keys[0];
        if traversal_keys.iter().any(|key| {
            key.circuit_id != first.circuit_id
                || key.epoch != first.epoch
                || key.expires_at != first.expires_at
        }) {
            return Err(OnionError::WrongScope);
        }
        Ok(Self {
            traversal_keys,
            direction,
            next_sequence: 0,
        })
    }

    pub fn seal(&mut self, cell_type: CellType, payload: &[u8]) -> Result<WireCell, OnionError> {
        let sequence = self.next_sequence;
        let mut compact = seal_compact(
            self.traversal_keys.last().expect("non-empty keys"),
            self.direction,
            sequence,
            cell_type as u8,
            payload,
        )?;
        for key in self.traversal_keys[..self.traversal_keys.len() - 1]
            .iter()
            .rev()
        {
            compact = seal_compact(key, self.direction, sequence, 0, &compact)?;
        }
        let cell = WireCell::from_compact(&compact)?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(OnionError::OutOfWindow)?;
        Ok(cell)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenedLayer {
    Forward(Box<WireCell>),
    Terminal {
        cell_type: CellType,
        payload: Vec<u8>,
    },
}

#[derive(Clone, Debug, Default)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u128,
}

impl ReplayWindow {
    fn check(&self, sequence: u64) -> Result<(), OnionError> {
        let Some(highest) = self.highest else {
            return if sequence == 0 {
                Ok(())
            } else {
                Err(OnionError::OutOfWindow)
            };
        };
        if sequence > highest {
            return if sequence - highest <= MAX_FUTURE_SEQUENCE_JUMP {
                Ok(())
            } else {
                Err(OnionError::OutOfWindow)
            };
        }
        let distance = highest - sequence;
        if distance >= REPLAY_WINDOW_BITS {
            return Err(OnionError::OutOfWindow);
        }
        if self.bitmap & (1u128 << distance) != 0 {
            return Err(OnionError::Replay);
        }
        Ok(())
    }

    fn commit(&mut self, sequence: u64) {
        match self.highest {
            None => {
                self.highest = Some(sequence);
                self.bitmap = 1;
            }
            Some(highest) if sequence > highest => {
                let shift = sequence - highest;
                self.bitmap = if shift >= REPLAY_WINDOW_BITS {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.highest = Some(sequence);
            }
            Some(highest) => self.bitmap |= 1u128 << (highest - sequence),
        }
    }
}

pub struct HopReceiver {
    keys: HopKeys,
    expected_direction: Direction,
    replay: ReplayWindow,
}

/// Per-relay duplex state. It can remove this relay's incoming layer and add
/// exactly this relay's outgoing reverse layer without possessing any other
/// relay's key.
pub struct HopDuplex {
    keys: HopKeys,
    forward_replay: ReplayWindow,
    reverse_replay: ReplayWindow,
    next_forward_sequence: u64,
    next_reverse_sequence: u64,
}

impl HopDuplex {
    pub fn new(keys: HopKeys) -> Self {
        Self {
            keys,
            forward_replay: ReplayWindow::default(),
            reverse_replay: ReplayWindow::default(),
            next_forward_sequence: 0,
            next_reverse_sequence: 0,
        }
    }

    pub fn open(
        &mut self,
        cell: &WireCell,
        direction: Direction,
        now: u64,
    ) -> Result<OpenedLayer, OnionError> {
        let replay = match direction {
            Direction::Forward => &mut self.forward_replay,
            Direction::Reverse => &mut self.reverse_replay,
        };
        open_layer(&self.keys, replay, cell, direction, now)
    }

    pub fn seal_terminal(
        &mut self,
        direction: Direction,
        cell_type: CellType,
        payload: &[u8],
    ) -> Result<WireCell, OnionError> {
        self.seal_layer(direction, cell_type as u8, payload)
    }

    pub fn wrap(&mut self, direction: Direction, inner: &WireCell) -> Result<WireCell, OnionError> {
        self.seal_layer(direction, 0, inner.compact()?)
    }

    fn seal_layer(
        &mut self,
        direction: Direction,
        layer_type: u8,
        payload: &[u8],
    ) -> Result<WireCell, OnionError> {
        let sequence = match direction {
            Direction::Forward => self.next_forward_sequence,
            Direction::Reverse => self.next_reverse_sequence,
        };
        let compact = seal_compact(&self.keys, direction, sequence, layer_type, payload)?;
        let cell = WireCell::from_compact(&compact)?;
        let next = sequence.checked_add(1).ok_or(OnionError::OutOfWindow)?;
        match direction {
            Direction::Forward => self.next_forward_sequence = next,
            Direction::Reverse => self.next_reverse_sequence = next,
        }
        Ok(cell)
    }
}

impl HopReceiver {
    pub fn new(keys: HopKeys, expected_direction: Direction) -> Self {
        Self {
            keys,
            expected_direction,
            replay: ReplayWindow::default(),
        }
    }

    pub fn open(&mut self, cell: &WireCell, now: u64) -> Result<OpenedLayer, OnionError> {
        open_layer(
            &self.keys,
            &mut self.replay,
            cell,
            self.expected_direction,
            now,
        )
    }
}

fn open_layer(
    keys: &HopKeys,
    replay: &mut ReplayWindow,
    cell: &WireCell,
    expected_direction: Direction,
    now: u64,
) -> Result<OpenedLayer, OnionError> {
    let header = parse_cell_header(&cell.0)?;
    if header.direction != expected_direction
        || header.circuit_id != keys.circuit_id
        || header.epoch != keys.epoch
        || header.expires_at != keys.expires_at
    {
        return Err(OnionError::WrongScope);
    }
    if header.expires_at <= now {
        return Err(OnionError::Expired);
    }
    replay.check(header.sequence)?;
    let ciphertext_end = CELL_HEADER_SIZE + header.ciphertext_len;
    let tag_start = ciphertext_end - TAG_SIZE;
    let mut plaintext = cell.0[CELL_HEADER_SIZE..tag_start].to_vec();
    let tag = Tag::from_slice(&cell.0[tag_start..ciphertext_end]);
    let mut aad = Vec::with_capacity(CELL_HEADER_SIZE + CELL_SIZE - ciphertext_end);
    aad.extend_from_slice(&cell.0[..CELL_HEADER_SIZE]);
    aad.extend_from_slice(&cell.0[ciphertext_end..]);
    let (key, nonce) = keys.key_and_nonce(header.direction, header.sequence);
    ChaCha20Poly1305::new(key.into())
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut plaintext, tag)
        .map_err(|_| OnionError::AuthenticationFailed)?;
    if plaintext.len() < LAYER_HEADER_SIZE {
        return Err(OnionError::InvalidEncoding);
    }
    let declared = u16::from_be_bytes([plaintext[1], plaintext[2]]) as usize;
    if declared != plaintext.len() - LAYER_HEADER_SIZE {
        return Err(OnionError::InvalidEncoding);
    }
    let data = &plaintext[LAYER_HEADER_SIZE..];
    let opened = if plaintext[0] == 0 {
        OpenedLayer::Forward(Box::new(WireCell::from_compact(data)?))
    } else {
        OpenedLayer::Terminal {
            cell_type: CellType::try_from(plaintext[0])?,
            payload: data.to_vec(),
        }
    };
    replay.commit(header.sequence);
    Ok(opened)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fragment {
    pub message_id: [u8; 16],
    pub index: u32,
    pub count: u32,
    pub total_len: u32,
    pub bytes: Vec<u8>,
}

impl Fragment {
    pub const MAX_BYTES: usize = MAX_LAYER_DATA - FRAGMENT_HEADER_SIZE;

    pub fn encode(&self) -> Result<Vec<u8>, OnionError> {
        self.validate()?;
        let mut encoded = Vec::with_capacity(FRAGMENT_HEADER_SIZE + self.bytes.len());
        encoded.extend_from_slice(&self.message_id);
        encoded.extend_from_slice(&self.index.to_be_bytes());
        encoded.extend_from_slice(&self.count.to_be_bytes());
        encoded.extend_from_slice(&self.total_len.to_be_bytes());
        encoded.extend_from_slice(&self.bytes);
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, OnionError> {
        if bytes.len() < FRAGMENT_HEADER_SIZE || bytes.len() > MAX_LAYER_DATA {
            return Err(OnionError::InvalidEncoding);
        }
        let fragment = Self {
            message_id: bytes[..16].try_into().expect("fixed message-id slice"),
            index: u32::from_be_bytes(bytes[16..20].try_into().expect("fixed index slice")),
            count: u32::from_be_bytes(bytes[20..24].try_into().expect("fixed count slice")),
            total_len: u32::from_be_bytes(bytes[24..28].try_into().expect("fixed length slice")),
            bytes: bytes[28..].to_vec(),
        };
        fragment.validate()?;
        Ok(fragment)
    }

    fn validate(&self) -> Result<(), OnionError> {
        if self.count == 0
            || self.count > MAX_FRAGMENT_COUNT
            || self.index >= self.count
            || self.total_len as usize > MAX_MESSAGE_SIZE
            || self.bytes.len() > Self::MAX_BYTES
            || (self.total_len == 0 && (self.count != 1 || !self.bytes.is_empty()))
            || (self.total_len > 0 && self.bytes.is_empty())
        {
            return Err(OnionError::InvalidEncoding);
        }
        Ok(())
    }
}

pub fn fragment_message(message_id: [u8; 16], bytes: &[u8]) -> Result<Vec<Fragment>, OnionError> {
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(OnionError::PayloadTooLarge);
    }
    if bytes.is_empty() {
        return Ok(vec![Fragment {
            message_id,
            index: 0,
            count: 1,
            total_len: 0,
            bytes: Vec::new(),
        }]);
    }
    let count = bytes.len().div_ceil(Fragment::MAX_BYTES);
    if count > MAX_FRAGMENT_COUNT as usize {
        return Err(OnionError::PayloadTooLarge);
    }
    Ok(bytes
        .chunks(Fragment::MAX_BYTES)
        .enumerate()
        .map(|(index, chunk)| Fragment {
            message_id,
            index: index as u32,
            count: count as u32,
            total_len: bytes.len() as u32,
            bytes: chunk.to_vec(),
        })
        .collect())
}

struct PartialMessage {
    count: u32,
    total_len: u32,
    received_bytes: usize,
    fragments: Vec<Option<Vec<u8>>>,
}

#[derive(Default)]
pub struct Reassembler {
    messages: HashMap<[u8; 16], PartialMessage>,
}

impl Reassembler {
    pub fn push(&mut self, fragment: Fragment) -> Result<Option<Vec<u8>>, OnionError> {
        fragment.validate()?;
        if !self.messages.contains_key(&fragment.message_id)
            && self.messages.len() >= MAX_INFLIGHT_MESSAGES
        {
            return Err(OnionError::FragmentCapacity);
        }
        let entry = self
            .messages
            .entry(fragment.message_id)
            .or_insert_with(|| PartialMessage {
                count: fragment.count,
                total_len: fragment.total_len,
                received_bytes: 0,
                fragments: vec![None; fragment.count as usize],
            });
        if entry.count != fragment.count || entry.total_len != fragment.total_len {
            return Err(OnionError::InvalidEncoding);
        }
        let slot = &mut entry.fragments[fragment.index as usize];
        if slot.is_some() {
            return Err(OnionError::Replay);
        }
        let received_bytes = entry
            .received_bytes
            .checked_add(fragment.bytes.len())
            .ok_or(OnionError::PayloadTooLarge)?;
        if received_bytes > entry.total_len as usize {
            return Err(OnionError::InvalidEncoding);
        }
        entry.received_bytes = received_bytes;
        *slot = Some(fragment.bytes);
        if entry.fragments.iter().any(Option::is_none) {
            return Ok(None);
        }
        if entry.received_bytes != entry.total_len as usize {
            return Err(OnionError::InvalidEncoding);
        }
        let completed = self
            .messages
            .remove(&fragment.message_id)
            .expect("entry exists");
        let mut message = Vec::with_capacity(completed.total_len as usize);
        for bytes in completed.fragments.into_iter().flatten() {
            message.extend_from_slice(&bytes);
        }
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_is_bounded_and_strict() {
        let mut window = ReplayWindow::default();
        assert_eq!(window.check(1), Err(OnionError::OutOfWindow));
        window.check(0).unwrap();
        window.commit(0);
        assert_eq!(window.check(0), Err(OnionError::Replay));
        window.check(2).unwrap();
        window.commit(2);
        window.check(1).unwrap();
        window.commit(1);
        assert_eq!(window.check(1), Err(OnionError::Replay));
        assert_eq!(window.check(67), Err(OnionError::OutOfWindow));
    }

    #[test]
    fn key_derivation_known_answer() {
        let context = SetupContext {
            circuit_id: [0x11; 16],
            hop: 2,
            epoch: 7,
            expires_at: 9_999,
        };
        let transcript = setup_transcript(context, [0x22; 32], [0x33; 32], [0x55; 32]);
        let (keys, confirmation) = derive_keys(&[0x44; 64], &transcript, context).unwrap();
        let mut vector = Vec::new();
        vector.extend_from_slice(&keys.forward_key[..]);
        vector.extend_from_slice(&keys.reverse_key[..]);
        vector.extend_from_slice(&keys.forward_nonce_prefix);
        vector.extend_from_slice(&keys.reverse_nonce_prefix);
        vector.extend_from_slice(&confirmation[..]);
        assert_eq!(
            hex::encode(vector),
            "d65f6c19c8decb3bb2e7432dbcc4c2f6fb92f7fd7e8c4a8f6bf039ce11befb3cf2cfa3b7422a3a3de306bedee73a5d61fa1e0ecf95bacf664a1778302290924e7e2909433214095d6f8df7db98bf65082206015cc6985e37ccf5bb9cf9ec73348291bbfe864dcdd6"
        );
    }
}
