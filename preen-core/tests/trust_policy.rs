use preen_core::plugin::{
    SignatureBundle, SignatureVerifier, TrustPolicy, VerificationInput, VerificationOutcome,
    VerifyError, verify_with_policy,
};

struct FixedVerifier {
    identity: &'static str,
}

impl SignatureVerifier for FixedVerifier {
    fn verify(&self, _input: VerificationInput) -> Result<VerificationOutcome, VerifyError> {
        Ok(VerificationOutcome {
            identity: self.identity.to_string(),
        })
    }
}

fn sample_input() -> VerificationInput {
    VerificationInput {
        manifest_bytes: Vec::new(),
        signature: SignatureBundle {
            signature: String::new(),
            certificate: String::new(),
            rekor_log_id: None,
        },
        expected_identity: None,
        expected_issuer: None,
    }
}

#[test]
fn verify_with_policy_rejects_empty_allowlist() {
    let policy = TrustPolicy {
        allowlist: Vec::new(),
        remote_policy_url: None,
        remote_policy_identity: None,
        require_signed: true,
    };
    let verifier = FixedVerifier {
        identity: "https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main",
    };
    let err = verify_with_policy(&verifier, &policy, sample_input()).unwrap_err();
    assert!(matches!(err, VerifyError::PolicyUnavailable(_)));
}

#[test]
fn verify_with_policy_rejects_non_allowlisted_identity() {
    let policy = TrustPolicy {
        allowlist: vec![
            "https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main"
                .to_string(),
        ],
        remote_policy_url: None,
        remote_policy_identity: None,
        require_signed: true,
    };
    let verifier = FixedVerifier {
        identity: "https://github.com/example/other/.github/workflows/release.yml@refs/heads/main",
    };
    let err = verify_with_policy(&verifier, &policy, sample_input()).unwrap_err();
    assert!(matches!(err, VerifyError::NotTrusted { .. }));
}

#[test]
fn verify_with_policy_accepts_allowlisted_identity() {
    let identity = "https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main";
    let policy = TrustPolicy {
        allowlist: vec![identity.to_string()],
        remote_policy_url: None,
        remote_policy_identity: None,
        require_signed: true,
    };
    let verifier = FixedVerifier { identity };
    let outcome = verify_with_policy(&verifier, &policy, sample_input()).unwrap();
    assert_eq!(outcome.identity, identity);
}
