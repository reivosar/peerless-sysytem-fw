use peerless_anonymous_auth::{
    AnonymousAuthError, AnonymousChallenge, AnonymousCredentialClient, AnonymousIssuer,
    AnonymousPresentation, AnonymousVerifier, CredentialPolicy, ScopeKeyDescriptor,
};
use peerless_core::NodeId;
use peerless_identity::NodeIdentity;
use peerless_ledger::Membership;
use std::collections::HashSet;
use tempfile::TempDir;

const NOW: u64 = 12_345;

struct Fixture {
    temporary: TempDir,
    issuer_identity: NodeIdentity,
    member_identity: NodeIdentity,
    membership: Membership,
    trusted: HashSet<NodeId>,
    policy: CredentialPolicy,
    issuer: AnonymousIssuer,
    verifier: AnonymousVerifier,
}

impl Fixture {
    fn new(max_nullifiers: usize, max_issues: u16) -> Self {
        let temporary = TempDir::new().unwrap();
        let issuer_identity =
            NodeIdentity::load_or_generate(temporary.path().join("issuer")).unwrap();
        let member_identity =
            NodeIdentity::load_or_generate(temporary.path().join("member")).unwrap();
        let membership = Membership::issue(
            "testnet".into(),
            member_identity.node_id().clone(),
            vec!["compute".into()],
            Some(NOW + 1_000),
            &issuer_identity,
        )
        .unwrap();
        let trusted = HashSet::from([issuer_identity.node_id().clone()]);
        let policy = CredentialPolicy {
            epoch_seconds: 60,
            max_issues_per_member_epoch: max_issues,
            max_active_scope_keys: 4,
            max_nullifiers,
        };
        let issuer = AnonymousIssuer::new(policy).unwrap();
        let verifier = AnonymousVerifier::new(policy).unwrap();
        Self {
            temporary,
            issuer_identity,
            member_identity,
            membership,
            trusted,
            policy,
            issuer,
            verifier,
        }
    }

    async fn challenge(&self, now: u64) -> AnonymousChallenge {
        let challenge = self
            .issuer
            .challenge(&self.issuer_identity, "testnet", "compute", now)
            .await
            .unwrap();
        self.verifier
            .add_descriptor(
                descriptor(&challenge),
                &self.trusted,
                now,
                self.temporary.path().join("descriptor-verify"),
            )
            .await
            .unwrap();
        challenge
    }

    async fn credential(&self, challenge: &AnonymousChallenge, now: u64) -> AnonymousPresentation {
        let (request, pending) = AnonymousCredentialClient::begin(challenge).unwrap();
        let response = self
            .issuer
            .issue(
                &self.membership,
                &self.trusted,
                &HashSet::new(),
                request,
                now,
                self.temporary.path().join("verify"),
            )
            .await
            .unwrap();
        AnonymousCredentialClient::finish(pending, response).unwrap()
    }
}

fn descriptor(challenge: &AnonymousChallenge) -> ScopeKeyDescriptor {
    ScopeKeyDescriptor {
        scope: challenge.scope.clone(),
        public_key: challenge.issuer_public_key.clone(),
        governance_issuer: challenge.governance_issuer.clone(),
        governance_public_key: challenge.governance_public_key.clone(),
        signature: challenge.descriptor_signature.clone(),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[tokio::test]
async fn valid_member_redeems_without_stable_identity_and_replay_fails() {
    let fixture = Fixture::new(8, 8);
    let challenge = fixture.challenge(NOW).await;
    let (request, pending) = AnonymousCredentialClient::begin(&challenge).unwrap();
    let request_debug = format!("{request:?}");
    assert!(request_debug.contains("request_bytes"));
    assert!(!request_debug.contains(&hex::encode(&request.request)));
    let pending_debug = format!("{pending:?}");
    assert!(pending_debug.contains("[REDACTED]"));
    let request_bytes = serde_json::to_vec(&request).unwrap();
    assert!(!contains(
        &request_bytes,
        fixture.member_identity.node_id().as_bytes()
    ));
    assert!(!contains(
        &request_bytes,
        fixture.member_identity.public_key_der()
    ));
    assert!(!contains(&request_bytes, &fixture.membership.signature));

    let response = fixture
        .issuer
        .issue(
            &fixture.membership,
            &fixture.trusted,
            &HashSet::new(),
            request,
            NOW,
            fixture.temporary.path().join("verify"),
        )
        .await
        .unwrap();
    let response_debug = format!("{response:?}");
    assert!(response_debug.contains("response_bytes"));
    assert!(!response_debug.contains(&hex::encode(&response.response)));
    let presentation = AnonymousCredentialClient::finish(pending, response).unwrap();
    let presentation_debug = format!("{presentation:?}");
    assert!(presentation_debug.contains("token_bytes"));
    assert!(!presentation_debug.contains(&hex::encode(&presentation.token)));
    let presentation_bytes = serde_json::to_vec(&presentation).unwrap();
    assert!(!contains(
        &presentation_bytes,
        fixture.member_identity.node_id().as_bytes()
    ));
    assert!(!contains(
        &presentation_bytes,
        fixture.member_identity.public_key_der()
    ));

    fixture
        .verifier
        .redeem(presentation.clone(), "testnet", "compute", NOW)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .verifier
            .redeem(presentation, "testnet", "compute", NOW)
            .await,
        Err(AnonymousAuthError::ReplayOrCapacity)
    );
}

#[tokio::test]
async fn independent_presentations_are_unlinkable_and_both_valid() {
    let fixture = Fixture::new(8, 8);
    let challenge = fixture.challenge(NOW).await;
    let first = fixture.credential(&challenge, NOW).await;
    let second = fixture.credential(&challenge, NOW).await;
    assert_ne!(first.token, second.token);
    fixture
        .verifier
        .redeem(first, "testnet", "compute", NOW)
        .await
        .unwrap();
    fixture
        .verifier
        .redeem(second, "testnet", "compute", NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn wrong_scope_expiry_mutation_and_malformed_tokens_fail_closed() {
    let fixture = Fixture::new(16, 16);
    let challenge = fixture.challenge(NOW).await;
    let original = fixture.credential(&challenge, NOW).await;

    assert_eq!(
        fixture
            .verifier
            .redeem(original.clone(), "other", "compute", NOW)
            .await,
        Err(AnonymousAuthError::InvalidScope)
    );
    assert_eq!(
        fixture
            .verifier
            .redeem(original.clone(), "testnet", "storage", NOW)
            .await,
        Err(AnonymousAuthError::InvalidScope)
    );
    assert_eq!(
        fixture
            .verifier
            .redeem(
                original.clone(),
                "testnet",
                "compute",
                original.scope.expires_at,
            )
            .await,
        Err(AnonymousAuthError::Expired)
    );

    let mut malformed = original.clone();
    malformed.token.push(0);
    assert_eq!(
        fixture
            .verifier
            .redeem(malformed, "testnet", "compute", NOW)
            .await,
        Err(AnonymousAuthError::InvalidEncoding)
    );

    let mut signature_mutation = original.clone();
    *signature_mutation.token.last_mut().unwrap() ^= 1;
    assert_eq!(
        fixture
            .verifier
            .redeem(signature_mutation, "testnet", "compute", NOW)
            .await,
        Err(AnonymousAuthError::VerificationFailed)
    );

    for mutate in 0..5 {
        let mut changed = original.clone();
        match mutate {
            0 => changed.scope.network_id = "other".into(),
            1 => changed.scope.permission = "storage".into(),
            2 => changed.scope.epoch += 1,
            3 => changed.scope.expires_at += 1,
            4 => changed.scope.issuer_key_id[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(fixture
            .verifier
            .redeem(changed, "testnet", "compute", NOW)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn revoked_wrong_permission_and_expired_members_cannot_issue() {
    let fixture = Fixture::new(8, 8);
    let challenge = fixture.challenge(NOW).await;

    let (request, _) = AnonymousCredentialClient::begin(&challenge).unwrap();
    assert_eq!(
        fixture
            .issuer
            .issue(
                &fixture.membership,
                &fixture.trusted,
                &HashSet::from([fixture.member_identity.node_id().clone()]),
                request,
                NOW,
                fixture.temporary.path().join("verify-revoked"),
            )
            .await,
        Err(AnonymousAuthError::Revoked)
    );

    let wrong_permission = Membership::issue(
        "testnet".into(),
        fixture.member_identity.node_id().clone(),
        vec!["storage".into()],
        Some(NOW + 1_000),
        &fixture.issuer_identity,
    )
    .unwrap();
    let (request, _) = AnonymousCredentialClient::begin(&challenge).unwrap();
    assert_eq!(
        fixture
            .issuer
            .issue(
                &wrong_permission,
                &fixture.trusted,
                &HashSet::new(),
                request,
                NOW,
                fixture.temporary.path().join("verify-permission"),
            )
            .await,
        Err(AnonymousAuthError::UnauthorizedMembership)
    );

    let expired = Membership::issue(
        "testnet".into(),
        fixture.member_identity.node_id().clone(),
        vec!["compute".into()],
        Some(NOW),
        &fixture.issuer_identity,
    )
    .unwrap();
    let (request, _) = AnonymousCredentialClient::begin(&challenge).unwrap();
    assert_eq!(
        fixture
            .issuer
            .issue(
                &expired,
                &fixture.trusted,
                &HashSet::new(),
                request,
                NOW,
                fixture.temporary.path().join("verify-expired"),
            )
            .await,
        Err(AnonymousAuthError::UnauthorizedMembership)
    );
}

#[tokio::test]
async fn malformed_blind_requests_fail_closed_without_spending_issuance_quota() {
    let fixture = Fixture::new(8, 1);
    let challenge = fixture.challenge(NOW).await;

    for mutation in 0..3 {
        let (mut request, _) = AnonymousCredentialClient::begin(&challenge).unwrap();
        match mutation {
            0 => request.request.truncate(2),
            1 => request.request[1] ^= 1,
            2 => request.request[2] ^= 1,
            _ => unreachable!(),
        }
        let expected = if mutation == 2 {
            AnonymousAuthError::InvalidScope
        } else {
            AnonymousAuthError::InvalidEncoding
        };
        assert_eq!(
            fixture
                .issuer
                .issue(
                    &fixture.membership,
                    &fixture.trusted,
                    &HashSet::new(),
                    request,
                    NOW,
                    fixture
                        .temporary
                        .path()
                        .join(format!("verify-malformed-{mutation}")),
                )
                .await,
            Err(expected)
        );
    }

    // Invalid traffic cannot exhaust the sole valid issuance allowance.
    let valid = fixture.credential(&challenge, NOW).await;
    fixture
        .verifier
        .redeem(valid, "testnet", "compute", NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn issuance_and_nullifier_storage_are_bounded() {
    let fixture = Fixture::new(1, 1);
    let challenge = fixture.challenge(NOW).await;
    let first = fixture.credential(&challenge, NOW).await;

    let (second_request, _) = AnonymousCredentialClient::begin(&challenge).unwrap();
    assert_eq!(
        fixture
            .issuer
            .issue(
                &fixture.membership,
                &fixture.trusted,
                &HashSet::new(),
                second_request,
                NOW,
                fixture.temporary.path().join("verify-limit"),
            )
            .await,
        Err(AnonymousAuthError::IssuanceLimit)
    );
    fixture
        .verifier
        .redeem(first, "testnet", "compute", NOW)
        .await
        .unwrap();

    let second_member =
        NodeIdentity::load_or_generate(fixture.temporary.path().join("second-member")).unwrap();
    let second_membership = Membership::issue(
        "testnet".into(),
        second_member.node_id().clone(),
        vec!["compute".into()],
        Some(NOW + 1_000),
        &fixture.issuer_identity,
    )
    .unwrap();
    let (request, pending) = AnonymousCredentialClient::begin(&challenge).unwrap();
    let response = fixture
        .issuer
        .issue(
            &second_membership,
            &fixture.trusted,
            &HashSet::new(),
            request,
            NOW,
            fixture.temporary.path().join("verify-second"),
        )
        .await
        .unwrap();
    let second = AnonymousCredentialClient::finish(pending, response).unwrap();
    assert_eq!(
        fixture
            .verifier
            .redeem(second, "testnet", "compute", NOW)
            .await,
        Err(AnonymousAuthError::ReplayOrCapacity)
    );
}

#[tokio::test]
async fn epoch_rotation_changes_keys_and_old_tokens_expire() {
    let fixture = Fixture::new(8, 8);
    let first_challenge = fixture.challenge(NOW).await;
    let first = fixture.credential(&first_challenge, NOW).await;
    let next_epoch = first_challenge.scope.expires_at;
    let second_challenge = fixture.challenge(next_epoch).await;
    assert_ne!(
        first_challenge.scope.issuer_key_id,
        second_challenge.scope.issuer_key_id
    );
    let second = fixture.credential(&second_challenge, next_epoch).await;
    assert_eq!(
        fixture
            .verifier
            .redeem(first, "testnet", "compute", next_epoch)
            .await,
        Err(AnonymousAuthError::Expired)
    );
    fixture
        .verifier
        .redeem(second, "testnet", "compute", next_epoch)
        .await
        .unwrap();
}

#[test]
fn policy_and_epoch_bounds_fail_closed() {
    assert_eq!(
        AnonymousIssuer::new(CredentialPolicy {
            epoch_seconds: 0,
            ..CredentialPolicy::default()
        })
        .err(),
        Some(AnonymousAuthError::InvalidPolicy)
    );
    let fixture = Fixture::new(8, 8);
    let (epoch, expiry) = fixture.policy.epoch(NOW).unwrap();
    assert_eq!(epoch, NOW / 60);
    assert!(expiry > NOW);
    assert!(expiry - NOW <= 60);
}

#[tokio::test]
async fn descriptor_store_is_idempotent_and_bounded() {
    let temporary = TempDir::new().unwrap();
    let governance = NodeIdentity::load_or_generate(temporary.path().join("governance")).unwrap();
    let trusted = HashSet::from([governance.node_id().clone()]);
    let issuer_policy = CredentialPolicy {
        max_active_scope_keys: 2,
        ..CredentialPolicy::default()
    };
    let verifier_policy = CredentialPolicy {
        max_active_scope_keys: 1,
        ..CredentialPolicy::default()
    };
    let issuer = AnonymousIssuer::new(issuer_policy).unwrap();
    let verifier = AnonymousVerifier::new(verifier_policy).unwrap();
    let first = issuer
        .challenge(&governance, "testnet", "compute", NOW)
        .await
        .unwrap();
    let first_descriptor = descriptor(&first);
    verifier
        .add_descriptor(
            first_descriptor.clone(),
            &trusted,
            NOW,
            temporary.path().join("verify-first"),
        )
        .await
        .unwrap();

    assert_eq!(
        verifier
            .add_descriptor(
                first_descriptor.clone(),
                &HashSet::new(),
                NOW,
                temporary.path().join("verify-untrusted"),
            )
            .await,
        Err(AnonymousAuthError::UnauthorizedMembership)
    );
    for mutate in 0..5 {
        let mut changed = first_descriptor.clone();
        match mutate {
            0 => changed.scope.permission.push('x'),
            1 => changed.public_key[0] ^= 1,
            2 => changed.governance_issuer = NodeId::derive(b"different issuer"),
            3 => changed.governance_public_key[0] ^= 1,
            4 => changed.signature[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(verifier
            .add_descriptor(
                changed,
                &trusted,
                NOW,
                temporary.path().join(format!("verify-mutation-{mutate}")),
            )
            .await
            .is_err());
    }
    verifier
        .add_descriptor(
            first_descriptor,
            &trusted,
            NOW,
            temporary.path().join("verify-repeat"),
        )
        .await
        .unwrap();

    let second = issuer
        .challenge(&governance, "testnet", "storage", NOW)
        .await
        .unwrap();
    assert_eq!(
        verifier
            .add_descriptor(
                descriptor(&second),
                &trusted,
                NOW,
                temporary.path().join("verify-second"),
            )
            .await,
        Err(AnonymousAuthError::KeyLimit)
    );

    let next_epoch = first.scope.expires_at;
    let rotated = issuer
        .challenge(&governance, "testnet", "compute", next_epoch)
        .await
        .unwrap();
    verifier
        .add_descriptor(
            descriptor(&rotated),
            &trusted,
            next_epoch,
            temporary.path().join("verify-rotated"),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn concurrent_scope_key_generation_is_serialized_and_bounded() {
    let temporary = TempDir::new().unwrap();
    let governance = NodeIdentity::load_or_generate(temporary.path().join("governance")).unwrap();
    let issuer = AnonymousIssuer::new(CredentialPolicy {
        max_active_scope_keys: 1,
        ..CredentialPolicy::default()
    })
    .unwrap();

    let (first, second) = tokio::join!(
        issuer.challenge(&governance, "testnet", "compute", NOW),
        issuer.challenge(&governance, "testnet", "compute", NOW),
    );
    assert_eq!(
        first.unwrap().scope.issuer_key_id,
        second.unwrap().scope.issuer_key_id
    );

    let (compute, storage) = tokio::join!(
        issuer.challenge(&governance, "testnet", "compute", NOW),
        issuer.challenge(&governance, "testnet", "storage", NOW),
    );
    assert!(compute.is_ok());
    assert_eq!(storage, Err(AnonymousAuthError::KeyLimit));
}

#[test]
fn scope_challenge_digest_known_answer_covers_every_public_field() {
    let scope = peerless_anonymous_auth::AuthorizationScope {
        version: 1,
        network_id: "known-network".into(),
        permission: "compute".into(),
        epoch: 42,
        expires_at: 2_580,
        issuer_key_id: [0x5a; 32],
    };
    let digest = scope.challenge_digest().unwrap();
    assert_eq!(
        hex::encode(digest),
        "65893a7621ddfde732ef7381cb27571784dfd49a791203e1465231318f118551"
    );

    for mutate in 0..6 {
        let mut changed = scope.clone();
        match mutate {
            0 => changed.version += 1,
            1 => changed.network_id.push('x'),
            2 => changed.permission.push('x'),
            3 => changed.epoch += 1,
            4 => changed.expires_at += 1,
            5 => changed.issuer_key_id[0] ^= 1,
            _ => unreachable!(),
        }
        assert_ne!(changed.challenge_digest().ok(), Some(digest));
    }
}
