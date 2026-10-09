//! Formal secret-free product evidence. Parsing alone never grants execution authority.
use crate::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct ProductIdentity {
    pub executable_name: String,
    pub product_name: String,
    pub sha256: Option<String>,
    pub publisher: Option<String>,
    pub signature_identity: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ts_rs::TS)]
#[serde(rename_all = "kebab-case")]
pub enum ClosureResult {
    SignedOut,
    StillSignedIn,
    Inconclusive,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ts_rs::TS)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationMethod {
    DisposableVm,
    ExistingLocalAdapter,
    SyntheticSafety,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ts_rs::TS)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationStatus {
    Validated,
    Observed,
    Incomplete,
    Rejected,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct ProductValidationRecord {
    pub format_version: u32,
    pub application_id: String,
    pub channel: String,
    pub product_identity: ProductIdentity,
    pub tested_version: String,
    pub storage_layout: String,
    pub artifact_families: Vec<String>,
    pub storage_ownership: StorageOwnership,
    pub authentication_closure: ClosureResult,
    pub preservation: PreservationState,
    pub known_losses: Vec<String>,
    pub repetitions: u32,
    pub test_date: String,
    pub validation_method: ValidationMethod,
    pub status: ValidationStatus,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedProduct {
    pub application_id: String,
    pub channel: String,
    pub product_identity: ProductIdentity,
    pub version: String,
    pub storage_layout: String,
    pub artifact_families: Vec<String>,
}
impl ProductValidationRecord {
    pub fn parse(input: &str) -> Result<Self, &'static str> {
        if input.len() > 64 * 1024 {
            return Err("validation-record-too-large");
        }
        let record: Self =
            serde_json::from_str(input).map_err(|_| "invalid-product-validation-json")?;
        record.validate()?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        let text =
            |s: &str| !s.trim().is_empty() && s.len() <= 512 && !s.chars().any(char::is_control);
        let code = |s: &str| {
            text(s)
                && s.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                && s.split('-').all(|part| !part.is_empty())
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        if self.format_version != 1
            || !code(&self.application_id)
            || !code(&self.channel)
            || !text(&self.product_identity.product_name)
            || !text(&self.tested_version)
            || !text(&self.storage_layout)
            || !text(&self.product_identity.executable_name)
            || self
                .product_identity
                .executable_name
                .contains(['/', '\\', ':'])
            || self
                .product_identity
                .publisher
                .as_ref()
                .is_some_and(|s| !text(s))
            || self
                .product_identity
                .signature_identity
                .as_ref()
                .is_some_and(|s| !text(s))
            || self.artifact_families.is_empty()
            || self.artifact_families.len() > 64
            || self.artifact_families.iter().any(|s| !code(s))
            || self
                .artifact_families
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.artifact_families.len()
            || self.known_losses.len() > 64
            || self.known_losses.iter().any(|s| !text(s))
            || self.repetitions > 1000
            || !valid_date(&self.test_date)
            || self.product_identity.sha256.as_ref().is_some_and(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err("invalid-product-validation-metadata");
        }
        if self.preservation == PreservationState::KnownLosses && self.known_losses.is_empty() {
            return Err("validation-known-losses-missing");
        }
        if self.validation_method == ValidationMethod::SyntheticSafety
            && self.authentication_closure != ClosureResult::Inconclusive
        {
            return Err("synthetic-authentication-proof-not-allowed");
        }
        if self.repetitions == 0 && self.authentication_closure != ClosureResult::Inconclusive {
            return Err("validation-closure-observation-missing");
        }
        if self.status == ValidationStatus::Validated
            && (self.validation_method != ValidationMethod::DisposableVm
                || self.repetitions < 2
                || self.authentication_closure != ClosureResult::SignedOut
                || self.preservation == PreservationState::Unknown
                || !matches!(
                    self.storage_ownership,
                    StorageOwnership::Exclusive | StorageOwnership::Corroborated
                )
                || self.product_identity.sha256.is_none())
        {
            return Err("product-validation-gates-incomplete");
        }
        Ok(())
    }
    /// Call only with a record admitted by the trusted catalog/maintainer boundary.
    /// Unknown observations fail closed; mismatched versions/channels/identity/layout are stale.
    pub fn bind(&self, observed: Option<&ObservedProduct>) -> Result<ScopeEvidence, &'static str> {
        self.validate()?;
        let source = "product-validation-record";
        let mut evidence = ScopeEvidence {
            storage_ownership: EvidenceState::new(
                self.storage_ownership,
                source,
                "product-storage-review",
            ),
            authentication_scope: EvidenceState::new(
                if self.status == ValidationStatus::Validated {
                    AuthenticationScope::Validated
                } else if self.authentication_closure == ClosureResult::SignedOut {
                    AuthenticationScope::Observed
                } else {
                    AuthenticationScope::Unknown
                },
                source,
                "product-closure-result",
            ),
            preservation: EvidenceState::new(
                self.preservation,
                source,
                "product-preservation-result",
            ),
            authority: if self.status == ValidationStatus::Validated {
                OperationAuthority::ReviewedCatalog
            } else {
                OperationAuthority::Unreviewed
            },
            ..Default::default()
        };
        if let Some(actual) = observed {
            let identity_matches = actual.application_id == self.application_id
                && actual.product_identity == self.product_identity;
            evidence.application_identity = EvidenceState::new(
                if identity_matches {
                    ApplicationIdentity::Exact
                } else {
                    ApplicationIdentity::Unknown
                },
                "runtime-product-identity",
                "product-identity-binding",
            );
            let current = identity_matches
                && actual.channel == self.channel
                && actual.version == self.tested_version
                && actual.storage_layout == self.storage_layout
                && actual.artifact_families == self.artifact_families;
            evidence.version_applicability = EvidenceState::new(
                if current {
                    VersionApplicability::Current
                } else {
                    VersionApplicability::Stale
                },
                "runtime-product-identity",
                "product-version-binding",
            );
        }
        Ok(evidence)
    }
}
fn valid_date(date: &str) -> bool {
    let parts: Vec<_> = date.split('-').collect();
    if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (
        parts[0].parse::<u32>(),
        parts[1].parse::<u32>(),
        parts[2].parse::<u32>(),
    ) else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    year >= 2000 && (1..=days).contains(&day)
}
