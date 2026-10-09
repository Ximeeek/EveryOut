//! Exact manifest registry targets under an owner-bound HKU mount. No values
//! are read; the engine applies its normal review/process/preservation gates.
use crate::{
    executor::ProcessGate,
    platform::{PlatformManifest, RegistryArtifact},
    CleaningMethod, Manifest, Root,
};
use everyout_core_model::*;
use everyout_engine::{EngineProvider, ProcessPreview};
use std::cell::RefCell;

pub struct RegistryExecutor<'a> {
    manifest: Manifest,
    instance: ProviderInstance,
    artifacts: Vec<(PlannedAction, RegistryArtifact)>,
    processes: &'a dyn ProcessGate,
    snapshot: RefCell<Option<SnapshotId>>,
}
impl<'a> RegistryExecutor<'a> {
    pub fn load(
        json: &str,
        hive: &str,
        user: UserId,
        processes: &'a dyn ProcessGate,
    ) -> Result<Self, ErrorKind> {
        let manifest = crate::load_manifest(json).map_err(|_| ErrorKind::InvalidManifest)?;
        if manifest.roots.len() != 1
            || !matches!(manifest.roots[0], Root::Registry { .. })
            || manifest.profiles.is_some()
            || manifest.session_locations.iter().any(|a| {
                a.artifact_family
                    .as_ref()
                    .is_none_or(|f| manifest.preserve.artifact_families.contains(f))
            })
        {
            return Err(ErrorKind::Unsupported);
        }
        let owner = OwnerIdentity {
            user_id: user,
            installation_id: InstallationId(manifest.id.clone()),
            root_id: RootId(manifest.roots[0].id().into()),
        };
        let instance = ProviderInstance {
            decision: crate::evidence::decision(
                &manifest,
                crate::evidence::catalog(&manifest),
                &[],
            ),
            provider_id: ProviderId(manifest.id.clone()),
            instance_id: InstanceId(format!("{}-registry", manifest.id)),
            owner: owner.clone(),
            profiles: vec![],
            confidence: manifest.confidence.level,
            detection_origin: DetectionOrigin::KnownProvider,
            evidence: vec![],
            issues: vec![],
        };
        let platform = PlatformManifest::load(json).map_err(|_| ErrorKind::InvalidManifest)?;
        let mut artifacts = Vec::new();
        for artifact in &manifest.session_locations {
            let method = manifest
                .cleaning_methods
                .iter()
                .find(|m| m.id() == artifact.method)
                .ok_or(ErrorKind::InvalidManifest)?;
            if !matches!(method, CleaningMethod::DeleteRegistryTarget { .. }) {
                return Err(ErrorKind::Unsupported);
            }
            let action = PlannedAction {
                action_id: ActionId(artifact.id.clone()),
                artifact_id: ArtifactId(artifact.id.clone()),
                root_id: owner.root_id.clone(),
                profile_id: None,
                method_id: method.id().into(),
                method: MethodKind::DeleteRegistryTarget,
                owner: owner.clone(),
                shared_owners: vec![],
                artifact_families: artifact.artifact_family.clone().into_iter().collect(),
                effects: method.effects().to_vec(),
                blockers: method.blockers().to_vec(),
                confirmations: vec![],
            };
            artifacts.push((
                action,
                platform
                    .registry_for_account(&artifact.id, hive)
                    .map_err(|e| e.kind)?,
            ));
        }
        Ok(Self {
            manifest,
            instance,
            artifacts,
            processes,
            snapshot: RefCell::new(None),
        })
    }
    fn issue(&self, phase: Phase, kind: ErrorKind) -> ProviderIssue {
        ProviderIssue {
            phase,
            provider_id: self.instance.provider_id.clone(),
            instance_id: Some(self.instance.instance_id.clone()),
            action_id: None,
            kind,
            os_code: None,
            explanation_code: "account-registry-operation-refused".into(),
            blocked: true,
        }
    }
    fn matches(&self, plan: &ProposedPlan) -> bool {
        plan.provider_id == self.instance.provider_id
            && plan.manifest_revision == self.manifest.revision
            && plan.support == self.manifest.support
            && plan.selection.account_mode == AccountMode::Current
            && plan.selection.instances == [self.instance.instance_id.clone()]
            && plan.selection.profiles.is_empty()
            && self.snapshot.borrow().as_ref() == Some(&plan.selection.snapshot_id)
            && plan.actions
                == self
                    .artifacts
                    .iter()
                    .map(|(a, _)| a.clone())
                    .collect::<Vec<_>>()
            && plan.risks == self.manifest.risks
    }
}
impl MetadataAccess for RegistryExecutor<'_> {
    fn observe(
        &self,
        owner: &OwnerIdentity,
        artifact: &ArtifactId,
    ) -> Result<MetadataObservation, ErrorKind> {
        if owner != &self.instance.owner {
            return Err(ErrorKind::ScopeViolation);
        }
        let (action, target) = self
            .artifacts
            .iter()
            .find(|(a, _)| &a.artifact_id == artifact)
            .ok_or(ErrorKind::ScopeViolation)?;
        let kind = self
            .manifest
            .session_locations
            .iter()
            .find(|a| a.id == action.artifact_id.0)
            .ok_or(ErrorKind::InvalidManifest)?
            .kind;
        Ok(MetadataObservation {
            artifact_id: artifact.clone(),
            kind,
            exists: target.exists().map_err(|e| e.kind)?,
            size: None,
        })
    }
}
impl LocalOperations for RegistryExecutor<'_> {
    fn apply(&self, plan: &ValidatedPlan, id: &ActionId) -> ActionOutcome {
        let outcome = (|| {
            if !self.matches(plan.plan()) {
                return Err(ErrorKind::StalePlan);
            }
            self.processes.revalidate()?;
            let (_, artifact) = self
                .artifacts
                .iter()
                .find(|(a, _)| &a.action_id == id)
                .ok_or(ErrorKind::ScopeViolation)?;
            artifact.delete(false).map(|m| m.status).map_err(|e| e.kind)
        })();
        match outcome {
            Ok(status) => ActionOutcome {
                action_id: id.clone(),
                status,
                issues: vec![],
            },
            Err(kind) => ActionOutcome {
                action_id: id.clone(),
                status: ActionStatus::Failed,
                issues: vec![self.issue(Phase::Execute, kind)],
            },
        }
    }
}
impl Provider for RegistryExecutor<'_> {
    fn detect(&self, cx: &DetectionContext<'_>) -> DetectionResult {
        if cx.account_mode != AccountMode::Current {
            return DetectionResult {
                snapshot_id: cx.snapshot_id.clone(),
                instances: vec![],
                observations: vec![],
                issues: vec![self.issue(Phase::Detect, ErrorKind::ScopeViolation)],
            };
        }
        self.snapshot.replace(Some(cx.snapshot_id.clone()));
        DetectionResult {
            snapshot_id: cx.snapshot_id.clone(),
            instances: vec![self.instance.clone()],
            observations: vec![],
            issues: vec![],
        }
    }
    fn describe(&self, instance: &ProviderInstance) -> ProviderDescription {
        ProviderDescription {
            descriptor: ProviderDescriptor {
                provider_id: self.instance.provider_id.clone(),
                name: self.manifest.name.clone(),
                category: self.manifest.category,
                revision: self.manifest.revision,
                support: self.manifest.support,
                evidence: vec![],
                limitations: self.manifest.limitations.clone(),
            },
            instance_id: instance.instance_id.clone(),
            profiles: vec![],
            risks: self.manifest.risks.clone(),
            expected_effects: self
                .manifest
                .cleaning_methods
                .iter()
                .flat_map(|m| m.effects().iter().cloned())
                .collect(),
        }
    }
    fn plan(&self, cx: &PlanContext<'_>, selection: &Selection) -> PlanResult {
        if self.snapshot.borrow().as_ref() != Some(&selection.snapshot_id)
            || cx.inventory.snapshot_id != selection.snapshot_id
            || cx.inventory.instances != [self.instance.clone()]
            || selection.account_mode != AccountMode::Current
            || selection.instances != [self.instance.instance_id.clone()]
            || !selection.profiles.is_empty()
        {
            return PlanResult::Blocked {
                issues: vec![self.issue(Phase::Plan, ErrorKind::StalePlan)],
            };
        }
        PlanResult::Ready(Box::new(ProposedPlan {
            scope_evidence: self.instance.decision.evidence.clone(),
            plan_id: PlanId(format!("{}-{}", self.manifest.id, selection.snapshot_id.0)),
            provider_id: self.instance.provider_id.clone(),
            manifest_revision: self.manifest.revision,
            support: self.manifest.support,
            selection: selection.clone(),
            actions: self.artifacts.iter().map(|(a, _)| a.clone()).collect(),
            risks: self.manifest.risks.clone(),
            blockers: vec![],
            confirmations: vec![],
            limitations: self.manifest.limitations.clone(),
        }))
    }
    fn execute(
        &self,
        cx: &OperationContext<'_>,
        plan: &ValidatedPlan,
        mode: ExecutionMode,
    ) -> ExecutionResult {
        let mut result = ExecutionResult {
            plan_id: plan.plan().plan_id.clone(),
            mode,
            outcomes: vec![],
            issues: vec![],
        };
        if !self.matches(plan.plan()) {
            result
                .issues
                .push(self.issue(Phase::Execute, ErrorKind::StalePlan));
            return result;
        }
        for action in &plan.plan().actions {
            let outcome = if (cx.cancelled)() {
                ActionOutcome {
                    action_id: action.action_id.clone(),
                    status: ActionStatus::Skipped,
                    issues: vec![self.issue(Phase::Execute, ErrorKind::Cancelled)],
                }
            } else if mode == ExecutionMode::Apply {
                cx.operations.apply(plan, &action.action_id)
            } else {
                match cx.operations.observe(&action.owner, &action.artifact_id) {
                    Ok(m) => ActionOutcome {
                        action_id: action.action_id.clone(),
                        status: if m.exists {
                            ActionStatus::WouldApply
                        } else {
                            ActionStatus::AlreadyAbsent
                        },
                        issues: vec![],
                    },
                    Err(kind) => ActionOutcome {
                        action_id: action.action_id.clone(),
                        status: ActionStatus::Blocked,
                        issues: vec![self.issue(Phase::Execute, kind)],
                    },
                }
            };
            result.outcomes.push(outcome);
        }
        result
    }
    fn verify(&self, cx: &VerificationContext<'_>, result: &ExecutionResult) -> VerificationResult {
        if !self.matches(cx.plan.plan()) || result.plan_id != cx.plan.plan().plan_id {
            return VerificationResult {
                plan_id: result.plan_id.clone(),
                artifacts: vec![],
                issues: vec![self.issue(Phase::Verify, ErrorKind::StalePlan)],
            };
        }
        let quiescent = self.processes.revalidate();
        let artifacts = cx
            .plan
            .plan()
            .actions
            .iter()
            .map(|a| {
                let observed = cx.metadata.observe(&a.owner, &a.artifact_id);
                let status = if result.mode == ExecutionMode::DryRun {
                    VerificationStatus::NotPerformed
                } else {
                    match &observed {
                        Ok(_) if quiescent.is_err() => VerificationStatus::Unknown,
                        Ok(m) if !m.exists => VerificationStatus::TargetAbsent,
                        Ok(_) => VerificationStatus::TargetPresent,
                        Err(ErrorKind::AccessDenied) => VerificationStatus::Inaccessible,
                        Err(_) => VerificationStatus::Unknown,
                    }
                };
                ArtifactVerification {
                    artifact_id: a.artifact_id.clone(),
                    status,
                    observation: observed.as_ref().ok().cloned(),
                    issues: quiescent
                        .err()
                        .or_else(|| observed.as_ref().err().copied())
                        .map(|kind| self.issue(Phase::Verify, kind))
                        .into_iter()
                        .collect(),
                }
            })
            .collect();
        VerificationResult {
            plan_id: result.plan_id.clone(),
            artifacts,
            issues: vec![],
        }
    }
    fn report(&self, result: &ProviderResult) -> SanitizedReport {
        let item = ReportItem {
            provider_id: self.instance.provider_id.clone(),
            instance_id: self.instance.instance_id.clone(),
            user_id: self.instance.owner.user_id.clone(),
            profiles: vec![],
            shared_effects: vec![],
            aggregate: result.aggregate,
            outcomes: result.execution.outcomes.clone(),
            verification: result.verification.artifacts.clone(),
            issues: result
                .execution
                .issues
                .iter()
                .chain(&result.verification.issues)
                .cloned()
                .collect(),
            risk_flags: self.manifest.risks.flags.clone(),
            limitations: self.manifest.limitations.clone(),
            authentication: Uncertainty::Unknown,
            browser_identity: Uncertainty::Unknown,
            sync: Uncertainty::Unknown,
            silent_sso: Uncertainty::Unknown,
            remote_revocation: Uncertainty::Unsupported,
        };
        let mut report = SanitizedReport {
            applications: vec![],
            browsers: vec![],
            windows_microsoft_and_dev_tools: vec![],
        };
        match self.manifest.category {
            Category::Application => report.applications.push(item),
            Category::Browser => report.browsers.push(item),
            Category::WindowsMicrosoftAndDevTools => {
                report.windows_microsoft_and_dev_tools.push(item)
            }
        }
        report
    }
}
impl EngineProvider for RegistryExecutor<'_> {
    fn process_preview(&self, plan: &ProposedPlan) -> Result<Vec<ProcessPreview>, ErrorKind> {
        if !self.matches(plan) {
            return Err(ErrorKind::StalePlan);
        }
        self.processes.preview()
    }
    fn close(&self, plan: &ValidatedPlan, policy: ProcessClosePolicy) -> Result<(), ErrorKind> {
        if !self.matches(plan.plan()) {
            return Err(ErrorKind::StalePlan);
        }
        self.processes.close(policy)
    }
    fn revalidate(&self, plan: &ValidatedPlan) -> Result<(), ErrorKind> {
        if !self.matches(plan.plan()) {
            return Err(ErrorKind::StalePlan);
        }
        self.processes.revalidate()
    }
    fn target_label(&self, action: &PlannedAction) -> String {
        format!("registry-artifact-{}", action.artifact_id.0)
    }
}
