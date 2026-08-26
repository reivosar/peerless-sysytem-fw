//! Anonymous, short-lived membership authorization.
//!
//! The stable membership identity is checked only while issuing a blind
//! RFC 9578 token. Redemption proves a public scope without carrying the
//! member identity or issuance transcript.

use async_trait::async_trait;
use openssl::{
    pkey::Private,
    rsa::{Padding, Rsa},
};
use peerless_core::NodeId;
use peerless_identity::{verify, NodeIdentity};
use peerless_ledger::Membership;
use privacypass::{
    auth::authenticate::TokenChallenge,
    public_tokens::{
        public_key_to_truncated_token_key_id,
        server::{serialize_public_key, OriginKeyStore, OriginServer},
        PublicKey, PublicToken, TokenRequest, TokenResponse,
    },
    Nonce, NonceStore, Serialize as _, TokenType,
};
use rand::rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const PROTOCOL_VERSION: u16 = 1;
const MAX_NETWORK_BYTES: usize = 128;
const MAX_PERMISSION_BYTES: usize = 128;
const MAX_REQUEST_BYTES: usize = 512;
const MAX_RESPONSE_BYTES: usize = 512;
const PUBLIC_REQUEST_BYTES: usize = 259;
const PUBLIC_RESPONSE_BYTES: usize = 256;
const PUBLIC_TOKEN_BYTES: usize = 354;
const ISSUER_NAME: &str = "peerless-anonymous-auth";

type PublicIssuerKey = PublicKey;
type PrivateIssuerKey = Rsa<Private>;

/// Public authorization class shared by an anonymity set.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScope {
    /// Anonymous authorization protocol version.
    pub version: u16,
    /// Permissioned Peerless network.
    pub network_id: String,
    /// Coarse permission class, shared by multiple members.
    pub permission: String,
    /// Common issuance epoch.
    pub epoch: u64,
    /// Common expiration time in Unix seconds.
    pub expires_at: u64,
    /// SHA-256 identifier of the scope-specific issuer public key.
    pub issuer_key_id: [u8; 32],
}

impl AuthorizationScope {
    fn validate(&self) -> Result<(), AnonymousAuthError> {
        if self.version != PROTOCOL_VERSION
            || self.network_id.is_empty()
            || self.network_id.len() > MAX_NETWORK_BYTES
            || self.permission.is_empty()
            || self.permission.len() > MAX_PERMISSION_BYTES
        {
            return Err(AnonymousAuthError::InvalidScope);
        }
        Ok(())
    }

    fn challenge(&self) -> Result<TokenChallenge, AnonymousAuthError> {
        self.validate()?;
        let encoded =
            hex::encode(serde_json::to_vec(self).map_err(|_| AnonymousAuthError::InvalidScope)?);
        Ok(TokenChallenge::new(
            TokenType::Public,
            ISSUER_NAME,
            None,
            &[encoded],
        ))
    }

    /// Returns the RFC 9578 challenge digest that is covered by the token.
    pub fn challenge_digest(&self) -> Result<[u8; 32], AnonymousAuthError> {
        self.challenge()?
            .digest()
            .map_err(|_| AnonymousAuthError::InvalidScope)
    }
}

/// Bounded epoch and storage policy for anonymous credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialPolicy {
    /// Duration of a common credential epoch.
    pub epoch_seconds: u64,
    /// Maximum blind issuances for one enrolled member in one epoch.
    pub max_issues_per_member_epoch: u16,
    /// Maximum concurrently retained scope keys.
    pub max_active_scope_keys: usize,
    /// Maximum retained redeemed nonces.
    pub max_nullifiers: usize,
}

impl Default for CredentialPolicy {
    fn default() -> Self {
        Self {
            epoch_seconds: 300,
            max_issues_per_member_epoch: 32,
            max_active_scope_keys: 16,
            max_nullifiers: 100_000,
        }
    }
}

impl CredentialPolicy {
    fn validate(self) -> Result<Self, AnonymousAuthError> {
        if self.epoch_seconds == 0
            || self.max_issues_per_member_epoch == 0
            || self.max_active_scope_keys == 0
            || self.max_active_scope_keys > 32
            || self.max_nullifiers == 0
        {
            return Err(AnonymousAuthError::InvalidPolicy);
        }
        Ok(self)
    }

    /// Returns the shared epoch and expiry for a timestamp.
    pub fn epoch(self, now: u64) -> Result<(u64, u64), AnonymousAuthError> {
        self.validate()?;
        let epoch = now / self.epoch_seconds;
        let expires_at = epoch
            .checked_add(1)
            .and_then(|value| value.checked_mul(self.epoch_seconds))
            .ok_or(AnonymousAuthError::InvalidScope)?;
        Ok((epoch, expires_at))
    }
}

/// Public challenge and issuer key distributed to eligible clients.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnonymousChallenge {
    /// Scope enforced by both issuer and verifier.
    pub scope: AuthorizationScope,
    /// DER SubjectPublicKeyInfo for the scope-specific RSA issuer key.
    pub issuer_public_key: Vec<u8>,
    /// Accountable control-plane issuer that signed the scope-key descriptor.
    pub governance_issuer: NodeId,
    /// Control-plane issuer public key.
    pub governance_public_key: Vec<u8>,
    /// Signature over every descriptor field.
    pub descriptor_signature: Vec<u8>,
}

/// Blind request. It contains no stable member identity.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlindCredentialRequest {
    /// Requested common scope.
    pub scope: AuthorizationScope,
    /// RFC 9578 TokenRequest bytes.
    pub request: Vec<u8>,
}

impl fmt::Debug for BlindCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlindCredentialRequest")
            .field("scope", &self.scope)
            .field("request_bytes", &self.request.len())
            .finish()
    }
}

/// Blind response returned after membership and permission checks.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlindCredentialResponse {
    /// RFC 9578 TokenResponse bytes.
    pub response: Vec<u8>,
}

impl fmt::Debug for BlindCredentialResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlindCredentialResponse")
            .field("response_bytes", &self.response.len())
            .finish()
    }
}

/// Process-local blinding state. It must never be logged or persisted.
pub struct PendingCredential {
    scope: AuthorizationScope,
    state: privacypass::public_tokens::TokenState,
}

impl fmt::Debug for PendingCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingCredential")
            .field("scope", &self.scope)
            .field("blinding_state", &"[REDACTED]")
            .finish()
    }
}

/// Anonymous bearer presentation. It has no enrollment identifier or key.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnonymousPresentation {
    /// Public common scope.
    pub scope: AuthorizationScope,
    /// RFC 9578 publicly verifiable token bytes.
    pub token: Vec<u8>,
}

impl fmt::Debug for AnonymousPresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnonymousPresentation")
            .field("scope", &self.scope)
            .field("token_bytes", &self.token.len())
            .finish()
    }
}

/// Public scope-key descriptor used for decentralized verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScopeKeyDescriptor {
    /// Exact public scope authorized by this key.
    pub scope: AuthorizationScope,
    /// DER SubjectPublicKeyInfo.
    pub public_key: Vec<u8>,
    /// Accountable control-plane issuer.
    pub governance_issuer: NodeId,
    /// Control-plane issuer public key.
    pub governance_public_key: Vec<u8>,
    /// Signature over scope, token key, and governance identity.
    pub signature: Vec<u8>,
}

impl ScopeKeyDescriptor {
    fn issue(
        scope: AuthorizationScope,
        public_key: Vec<u8>,
        issuer: &NodeIdentity,
    ) -> Result<Self, AnonymousAuthError> {
        let mut descriptor = Self {
            scope,
            public_key,
            governance_issuer: issuer.node_id().clone(),
            governance_public_key: issuer.public_key_der().to_vec(),
            signature: Vec::new(),
        };
        descriptor.signature = issuer
            .sign(&descriptor.payload()?)
            .map_err(|_| AnonymousAuthError::VerificationFailed)?;
        Ok(descriptor)
    }

    fn payload(&self) -> Result<Vec<u8>, AnonymousAuthError> {
        serde_json::to_vec(&(
            &self.scope,
            &self.public_key,
            &self.governance_issuer,
            &self.governance_public_key,
        ))
        .map_err(|_| AnonymousAuthError::InvalidEncoding)
    }

    fn verify(
        &self,
        trusted_issuers: &HashSet<NodeId>,
        temporary: impl AsRef<Path>,
    ) -> Result<bool, AnonymousAuthError> {
        Ok(trusted_issuers.contains(&self.governance_issuer)
            && NodeId::derive(&self.governance_public_key) == self.governance_issuer
            && verify(
                &self.governance_public_key,
                &self.payload()?,
                &self.signature,
                temporary,
            )
            .map_err(|_| AnonymousAuthError::VerificationFailed)?)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AnonymousAuthError {
    #[error("anonymous credential policy is invalid")]
    InvalidPolicy,
    #[error("anonymous credential scope is invalid")]
    InvalidScope,
    #[error("membership is not authorized for anonymous issuance")]
    UnauthorizedMembership,
    #[error("member has been revoked")]
    Revoked,
    #[error("anonymous credential issuance limit reached")]
    IssuanceLimit,
    #[error("anonymous credential key limit reached")]
    KeyLimit,
    #[error("anonymous credential is expired")]
    Expired,
    #[error("anonymous credential encoding is invalid")]
    InvalidEncoding,
    #[error("anonymous credential cryptographic verification failed")]
    VerificationFailed,
    #[error("anonymous credential was already redeemed or storage is full")]
    ReplayOrCapacity,
}

#[derive(Default)]
struct OpenSslIssuerKeys(Mutex<HashMap<u8, PrivateIssuerKey>>);

impl OpenSslIssuerKeys {
    fn insert(&self, id: u8, key: PrivateIssuerKey) -> bool {
        let mut keys = self.0.lock().expect("issuer key lock poisoned");
        if keys.contains_key(&id) {
            return false;
        }
        keys.insert(id, key);
        true
    }

    fn get(&self, id: &u8) -> Option<PrivateIssuerKey> {
        self.0
            .lock()
            .expect("issuer key lock poisoned")
            .get(id)
            .cloned()
    }

    fn remove(&self, id: &u8) -> bool {
        self.0
            .lock()
            .expect("issuer key lock poisoned")
            .remove(id)
            .is_some()
    }
}

#[derive(Default)]
struct MemoryOriginKeyStore(Mutex<HashMap<u8, Vec<PublicIssuerKey>>>);

impl MemoryOriginKeyStore {
    fn remove_exact(&self, id: u8, expected_der: &[u8]) {
        let mut keys = self.0.lock().expect("origin key lock poisoned");
        if let Some(values) = keys.get_mut(&id) {
            values.retain(|key| {
                serialize_public_key(key)
                    .map(|der| der != expected_der)
                    .unwrap_or(true)
            });
            if values.is_empty() {
                keys.remove(&id);
            }
        }
    }
}

#[async_trait]
impl OriginKeyStore for MemoryOriginKeyStore {
    async fn insert(&self, id: u8, key: PublicIssuerKey) {
        self.0
            .lock()
            .expect("origin key lock poisoned")
            .entry(id)
            .or_default()
            .push(key);
    }

    async fn get(&self, id: &u8) -> Vec<PublicIssuerKey> {
        self.0
            .lock()
            .expect("origin key lock poisoned")
            .get(id)
            .cloned()
            .unwrap_or_default()
    }

    async fn remove(&self, id: &u8) -> bool {
        self.0
            .lock()
            .expect("origin key lock poisoned")
            .remove(id)
            .is_some()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NonceState {
    Reserved,
    Committed,
}

struct BoundedNonceStore {
    values: Mutex<HashMap<Nonce, (NonceState, u64)>>,
    max_entries: usize,
    retention_seconds: u64,
}

impl BoundedNonceStore {
    fn new(max_entries: usize, retention_seconds: u64) -> Self {
        Self {
            values: Mutex::new(HashMap::new()),
            max_entries,
            retention_seconds,
        }
    }
}

#[async_trait]
impl NonceStore for BoundedNonceStore {
    async fn reserve(&self, nonce: &Nonce) -> bool {
        let now = unix_seconds();
        let mut values = self.values.lock().expect("nullifier lock poisoned");
        values.retain(|_, (_, expiry)| *expiry > now);
        if values.contains_key(nonce) || values.len() >= self.max_entries {
            return false;
        }
        values.insert(
            *nonce,
            (
                NonceState::Reserved,
                now.saturating_add(self.retention_seconds),
            ),
        );
        true
    }

    async fn commit(&self, nonce: &Nonce) {
        if let Some((state, _)) = self
            .values
            .lock()
            .expect("nullifier lock poisoned")
            .get_mut(nonce)
        {
            *state = NonceState::Committed;
        }
    }

    async fn release(&self, nonce: &Nonce) {
        let mut values = self.values.lock().expect("nullifier lock poisoned");
        if values
            .get(nonce)
            .is_some_and(|(state, _)| *state == NonceState::Reserved)
        {
            values.remove(nonce);
        }
    }
}

/// Membership-aware blind issuer with scope-specific rotating keys.
pub struct AnonymousIssuer {
    policy: CredentialPolicy,
    keys: OpenSslIssuerKeys,
    descriptors: Mutex<HashMap<AuthorizationScope, ScopeKeyDescriptor>>,
    issuance: Mutex<HashMap<(NodeId, u64), u16>>,
    key_generation: tokio::sync::Mutex<()>,
}

impl AnonymousIssuer {
    pub fn new(policy: CredentialPolicy) -> Result<Self, AnonymousAuthError> {
        Ok(Self {
            policy: policy.validate()?,
            keys: OpenSslIssuerKeys::default(),
            descriptors: Mutex::new(HashMap::new()),
            issuance: Mutex::new(HashMap::new()),
            key_generation: tokio::sync::Mutex::new(()),
        })
    }

    /// Creates or returns the common challenge for a permission and current epoch.
    pub async fn challenge(
        &self,
        governance_issuer: &NodeIdentity,
        network_id: &str,
        permission: &str,
        now: u64,
    ) -> Result<AnonymousChallenge, AnonymousAuthError> {
        validate_public_class(network_id, permission)?;
        let _generation_guard = self.key_generation.lock().await;
        self.prune(now).await;
        let (epoch, expires_at) = self.policy.epoch(now)?;

        if let Some(existing) = self
            .descriptors
            .lock()
            .expect("descriptor lock poisoned")
            .values()
            .find(|descriptor| {
                descriptor.scope.network_id == network_id
                    && descriptor.scope.permission == permission
                    && descriptor.scope.epoch == epoch
                    && descriptor.scope.expires_at == expires_at
            })
            .cloned()
        {
            return Ok(AnonymousChallenge {
                scope: existing.scope,
                issuer_public_key: existing.public_key,
                governance_issuer: existing.governance_issuer,
                governance_public_key: existing.governance_public_key,
                descriptor_signature: existing.signature,
            });
        }

        if self
            .descriptors
            .lock()
            .expect("descriptor lock poisoned")
            .len()
            >= self.policy.max_active_scope_keys
        {
            return Err(AnonymousAuthError::KeyLimit);
        }

        let mut generated_public_key = None;
        for _ in 0..100 {
            let private_key =
                Rsa::generate(2048).map_err(|_| AnonymousAuthError::VerificationFailed)?;
            let public_pkcs1 = private_key
                .public_key_to_der_pkcs1()
                .map_err(|_| AnonymousAuthError::VerificationFailed)?;
            let public_key = PublicKey::from_der(&public_pkcs1)
                .map_err(|_| AnonymousAuthError::VerificationFailed)?;
            let public_key_der = serialize_public_key(&public_key)
                .map_err(|_| AnonymousAuthError::VerificationFailed)?;
            let truncated = public_key_to_truncated_token_key_id(&public_key)
                .map_err(|_| AnonymousAuthError::VerificationFailed)?;
            if self.keys.insert(truncated, private_key) {
                generated_public_key = Some(public_key_der);
                break;
            }
        }
        let public_key_der = generated_public_key.ok_or(AnonymousAuthError::KeyLimit)?;
        let issuer_key_id: [u8; 32] = Sha256::digest(&public_key_der).into();
        let scope = AuthorizationScope {
            version: PROTOCOL_VERSION,
            network_id: network_id.to_owned(),
            permission: permission.to_owned(),
            epoch,
            expires_at,
            issuer_key_id,
        };
        scope.validate()?;
        let descriptor =
            ScopeKeyDescriptor::issue(scope.clone(), public_key_der.clone(), governance_issuer)?;
        self.descriptors
            .lock()
            .expect("descriptor lock poisoned")
            .insert(scope.clone(), descriptor.clone());
        Ok(AnonymousChallenge {
            scope,
            issuer_public_key: public_key_der,
            governance_issuer: descriptor.governance_issuer,
            governance_public_key: descriptor.governance_public_key,
            descriptor_signature: descriptor.signature,
        })
    }

    /// Blindly signs only after validating stable membership at issuance time.
    pub async fn issue(
        &self,
        membership: &Membership,
        trusted_issuers: &HashSet<NodeId>,
        revoked_members: &HashSet<NodeId>,
        request: BlindCredentialRequest,
        now: u64,
        verification_temporary: impl AsRef<Path>,
    ) -> Result<BlindCredentialResponse, AnonymousAuthError> {
        request.scope.validate()?;
        if revoked_members.contains(&membership.member) {
            return Err(AnonymousAuthError::Revoked);
        }
        if !membership
            .verify(trusted_issuers, now, verification_temporary)
            .map_err(|_| AnonymousAuthError::UnauthorizedMembership)?
            || membership.network_id != request.scope.network_id
            || !membership.permissions.contains(&request.scope.permission)
        {
            return Err(AnonymousAuthError::UnauthorizedMembership);
        }
        let (expected_epoch, expected_expiry) = self.policy.epoch(now)?;
        if request.scope.epoch != expected_epoch || request.scope.expires_at != expected_expiry {
            return Err(AnonymousAuthError::InvalidScope);
        }
        if request.request.len() > MAX_REQUEST_BYTES {
            return Err(AnonymousAuthError::InvalidEncoding);
        }
        let descriptor = self
            .descriptors
            .lock()
            .expect("descriptor lock poisoned")
            .get(&request.scope)
            .cloned()
            .ok_or(AnonymousAuthError::InvalidScope)?;
        if key_id(&descriptor.public_key)? != request.scope.issuer_key_id {
            return Err(AnonymousAuthError::InvalidScope);
        }

        if request.request.len() != PUBLIC_REQUEST_BYTES
            || u16::from_be_bytes([request.request[0], request.request[1]])
                != TokenType::Public as u16
        {
            return Err(AnonymousAuthError::InvalidEncoding);
        }
        let public_key = PublicKey::from_spki(&descriptor.public_key)
            .map_err(|_| AnonymousAuthError::InvalidEncoding)?;
        let expected_truncated = public_key_to_truncated_token_key_id(&public_key)
            .map_err(|_| AnonymousAuthError::InvalidEncoding)?;
        if request.request[2] != expected_truncated {
            return Err(AnonymousAuthError::InvalidScope);
        }

        // Malformed requests must not consume a member's bounded issuance
        // allowance. Count only after the full public request envelope and
        // scope-specific key selection have been validated.
        {
            let mut issuance = self.issuance.lock().expect("issuance lock poisoned");
            issuance.retain(|(_, epoch), _| *epoch >= expected_epoch);
            let count = issuance
                .entry((membership.member.clone(), expected_epoch))
                .or_default();
            if *count >= self.policy.max_issues_per_member_epoch {
                return Err(AnonymousAuthError::IssuanceLimit);
            }
            *count += 1;
        }
        let private_key = self
            .keys
            .get(&expected_truncated)
            .ok_or(AnonymousAuthError::InvalidScope)?;
        let mut response = vec![0u8; PUBLIC_RESPONSE_BYTES];
        let written = private_key
            .private_decrypt(&request.request[3..], &mut response, Padding::NONE)
            .map_err(|_| AnonymousAuthError::VerificationFailed)?;
        if written != PUBLIC_RESPONSE_BYTES {
            return Err(AnonymousAuthError::VerificationFailed);
        }
        Ok(BlindCredentialResponse { response })
    }

    /// Removes expired issuer keys and member issuance counters.
    pub async fn prune(&self, now: u64) {
        let expired = {
            let descriptors = self.descriptors.lock().expect("descriptor lock poisoned");
            descriptors
                .iter()
                .filter(|(scope, _)| scope.expires_at <= now)
                .map(|(scope, descriptor)| (scope.clone(), descriptor.public_key.clone()))
                .collect::<Vec<_>>()
        };
        for (scope, public_key_der) in expired {
            if let Ok(public_key) = PublicKey::from_spki(&public_key_der) {
                if let Ok(id) = public_key_to_truncated_token_key_id(&public_key) {
                    self.keys.remove(&id);
                }
            }
            self.descriptors
                .lock()
                .expect("descriptor lock poisoned")
                .remove(&scope);
        }
        if let Ok((epoch, _)) = self.policy.epoch(now) {
            self.issuance
                .lock()
                .expect("issuance lock poisoned")
                .retain(|(_, value_epoch), _| *value_epoch >= epoch);
        }
    }
}

/// Client functions for blind request construction and finalization.
pub struct AnonymousCredentialClient;

impl AnonymousCredentialClient {
    pub fn begin(
        challenge: &AnonymousChallenge,
    ) -> Result<(BlindCredentialRequest, PendingCredential), AnonymousAuthError> {
        challenge.scope.validate()?;
        if key_id(&challenge.issuer_public_key)? != challenge.scope.issuer_key_id {
            return Err(AnonymousAuthError::InvalidScope);
        }
        let public_key = PublicKey::from_spki(&challenge.issuer_public_key)
            .map_err(|_| AnonymousAuthError::InvalidEncoding)?;
        let token_challenge = challenge.scope.challenge()?;
        let (request, state) = TokenRequest::new(&mut rng(), public_key, &token_challenge)
            .map_err(|_| AnonymousAuthError::VerificationFailed)?;
        let request = request
            .tls_serialize_detached()
            .map_err(|_| AnonymousAuthError::InvalidEncoding)?;
        Ok((
            BlindCredentialRequest {
                scope: challenge.scope.clone(),
                request,
            },
            PendingCredential {
                scope: challenge.scope.clone(),
                state,
            },
        ))
    }

    pub fn finish(
        pending: PendingCredential,
        response: BlindCredentialResponse,
    ) -> Result<AnonymousPresentation, AnonymousAuthError> {
        if response.response.len() > MAX_RESPONSE_BYTES {
            return Err(AnonymousAuthError::InvalidEncoding);
        }
        let token_response: TokenResponse = decode_exact(&response.response, MAX_RESPONSE_BYTES)?;
        let token = token_response
            .issue_token(&pending.state)
            .map_err(|_| AnonymousAuthError::VerificationFailed)?;
        Ok(AnonymousPresentation {
            scope: pending.scope,
            token: token
                .tls_serialize_detached()
                .map_err(|_| AnonymousAuthError::InvalidEncoding)?,
        })
    }
}

/// Offline verifier using governance-approved public scope keys.
pub struct AnonymousVerifier {
    policy: CredentialPolicy,
    server: OriginServer,
    keys: MemoryOriginKeyStore,
    descriptors: Mutex<HashMap<AuthorizationScope, ScopeKeyDescriptor>>,
    nonces: BoundedNonceStore,
}

impl AnonymousVerifier {
    pub fn new(policy: CredentialPolicy) -> Result<Self, AnonymousAuthError> {
        let policy = policy.validate()?;
        Ok(Self {
            policy,
            server: OriginServer::new(),
            keys: MemoryOriginKeyStore::default(),
            descriptors: Mutex::new(HashMap::new()),
            nonces: BoundedNonceStore::new(policy.max_nullifiers, policy.epoch_seconds),
        })
    }

    /// Adds a governance-approved descriptor after strict scope/key checks.
    pub async fn add_descriptor(
        &self,
        descriptor: ScopeKeyDescriptor,
        trusted_issuers: &HashSet<NodeId>,
        now: u64,
        verification_temporary: impl AsRef<Path>,
    ) -> Result<(), AnonymousAuthError> {
        descriptor.scope.validate()?;
        let expected_expiry = descriptor
            .scope
            .epoch
            .checked_add(1)
            .and_then(|epoch| epoch.checked_mul(self.policy.epoch_seconds))
            .ok_or(AnonymousAuthError::InvalidScope)?;
        if descriptor.scope.expires_at != expected_expiry {
            return Err(AnonymousAuthError::InvalidScope);
        }
        if descriptor.scope.expires_at <= now {
            return Err(AnonymousAuthError::Expired);
        }
        if !descriptor.verify(trusted_issuers, verification_temporary)? {
            return Err(AnonymousAuthError::UnauthorizedMembership);
        }
        if key_id(&descriptor.public_key)? != descriptor.scope.issuer_key_id {
            return Err(AnonymousAuthError::InvalidScope);
        }
        let public_key = PublicKey::from_spki(&descriptor.public_key)
            .map_err(|_| AnonymousAuthError::InvalidEncoding)?;
        let truncated = public_key_to_truncated_token_key_id(&public_key)
            .map_err(|_| AnonymousAuthError::InvalidEncoding)?;
        self.prune(now);
        {
            let mut descriptors = self.descriptors.lock().expect("descriptor lock poisoned");
            if let Some(existing) = descriptors.get(&descriptor.scope) {
                return if existing == &descriptor {
                    Ok(())
                } else {
                    Err(AnonymousAuthError::InvalidScope)
                };
            }
            if descriptors.len() >= self.policy.max_active_scope_keys {
                return Err(AnonymousAuthError::KeyLimit);
            }
            descriptors.insert(descriptor.scope.clone(), descriptor);
        }
        self.keys.insert(truncated, public_key).await;
        Ok(())
    }

    /// Removes expired public descriptors without disturbing colliding live keys.
    pub fn prune(&self, now: u64) {
        let expired = {
            let descriptors = self.descriptors.lock().expect("descriptor lock poisoned");
            descriptors
                .iter()
                .filter(|(scope, _)| scope.expires_at <= now)
                .map(|(scope, descriptor)| (scope.clone(), descriptor.public_key.clone()))
                .collect::<Vec<_>>()
        };
        for (scope, public_key_der) in expired {
            self.descriptors
                .lock()
                .expect("descriptor lock poisoned")
                .remove(&scope);
            if let Ok(public_key) = PublicKey::from_spki(&public_key_der) {
                if let Ok(id) = public_key_to_truncated_token_key_id(&public_key) {
                    self.keys.remove_exact(id, &public_key_der);
                }
            }
        }
    }

    /// Verifies scope, expiry, signature, and one-time use without an online issuer.
    pub async fn redeem(
        &self,
        presentation: AnonymousPresentation,
        expected_network: &str,
        expected_permission: &str,
        now: u64,
    ) -> Result<(), AnonymousAuthError> {
        presentation.scope.validate()?;
        if presentation.scope.network_id != expected_network
            || presentation.scope.permission != expected_permission
        {
            return Err(AnonymousAuthError::InvalidScope);
        }
        let (epoch, expiry) = self.policy.epoch(now)?;
        if presentation.scope.epoch != epoch || presentation.scope.expires_at != expiry {
            return Err(AnonymousAuthError::Expired);
        }
        self.prune(now);
        if presentation.token.len() != PUBLIC_TOKEN_BYTES {
            return Err(AnonymousAuthError::InvalidEncoding);
        }
        let descriptor = self
            .descriptors
            .lock()
            .expect("descriptor lock poisoned")
            .get(&presentation.scope)
            .cloned()
            .ok_or(AnonymousAuthError::InvalidScope)?;
        if key_id(&descriptor.public_key)? != presentation.scope.issuer_key_id {
            return Err(AnonymousAuthError::InvalidScope);
        }
        let token: PublicToken = decode_exact(&presentation.token, PUBLIC_TOKEN_BYTES)?;
        if token.token_key_id() != &presentation.scope.issuer_key_id {
            return Err(AnonymousAuthError::InvalidScope);
        }
        let expected_digest = presentation
            .scope
            .challenge()?
            .digest()
            .map_err(|_| AnonymousAuthError::InvalidScope)?;
        if token.challenge_digest() != &expected_digest {
            return Err(AnonymousAuthError::InvalidScope);
        }
        self.server
            .redeem_token(&self.keys, &self.nonces, token)
            .await
            .map_err(|error| match error {
                privacypass::common::errors::RedeemTokenError::DoubleSpending => {
                    AnonymousAuthError::ReplayOrCapacity
                }
                _ => AnonymousAuthError::VerificationFailed,
            })
    }
}

fn validate_public_class(network_id: &str, permission: &str) -> Result<(), AnonymousAuthError> {
    if network_id.is_empty()
        || network_id.len() > MAX_NETWORK_BYTES
        || permission.is_empty()
        || permission.len() > MAX_PERMISSION_BYTES
    {
        return Err(AnonymousAuthError::InvalidScope);
    }
    Ok(())
}

fn key_id(public_key_der: &[u8]) -> Result<[u8; 32], AnonymousAuthError> {
    if public_key_der.len() > 1024 {
        return Err(AnonymousAuthError::InvalidEncoding);
    }
    Ok(Sha256::digest(public_key_der).into())
}

fn decode_exact<T: privacypass::Deserialize>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, AnonymousAuthError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(AnonymousAuthError::InvalidEncoding);
    }
    let mut remaining = bytes;
    let value =
        T::tls_deserialize(&mut remaining).map_err(|_| AnonymousAuthError::InvalidEncoding)?;
    if !remaining.is_empty() {
        return Err(AnonymousAuthError::InvalidEncoding);
    }
    Ok(value)
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
