use everyout_core_model::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

macro_rules! model {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
    };
}
macro_rules! vocabulary {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        #[serde(rename_all = "kebab-case")]
        pub enum $name { $($variant),+ }
    };
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum WindowsVersion {
    #[serde(rename = "windows-10")]
    Windows10,
    #[serde(rename = "windows-11")]
    Windows11,
}
vocabulary!(Availability {
    Available,
    Unavailable,
    Unknown
});
vocabulary!(LogoutSurface {
    LocalApp,
    BrowserIdentity,
    Remote
});
vocabulary!(Ownership {
    Application,
    BrowserProfile,
    SharedIdentity,
    DeveloperTool
});
vocabulary!(RegistryHive { CurrentUser });

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[schemars(range(min = 1, max = 1))]
    pub format_version: u32,
    #[schemars(regex(pattern = "^[a-z][a-z0-9]*(-[a-z0-9]+)*$"))]
    pub id: String,
    #[schemars(range(min = 1))]
    pub revision: u64,
    #[schemars(length(min = 1))]
    pub name: String,
    pub category: Category,
    pub support: Support,
    pub compatibility: Compatibility,
    pub identity: Identity,
    pub detection: Detection,
    #[schemars(length(min = 1))]
    pub roots: Vec<Root>,
    pub profiles: Option<Profiles>,
    #[schemars(length(min = 1))]
    pub session_locations: Vec<SessionLocation>,
    #[schemars(length(min = 1))]
    pub cleaning_methods: Vec<CleaningMethod>,
    pub preserve: Preservation,
    pub true_logout: TrueLogout,
    pub risks: RiskAssessment,
    pub confidence: EvidenceConfidence,
    #[schemars(length(min = 1))]
    pub evidence: Vec<Evidence>,
    pub limitations: Vec<String>,
    pub open_spikes: Vec<String>,
    #[serde(default)]
    pub extensions: Option<ExtensionPolicy>,
    #[serde(default)]
    pub application: Option<ApplicationKind>,
    #[serde(default)]
    pub sources: Option<Vec<String>>,
}
vocabulary!(ApplicationKind {
    ElectronCef,
    Webview2,
    Store,
    GamingLauncher
});
model!(Compatibility { os: Vec<WindowsVersion>, channel: String, product_versions: String });
model!(Identity {
    browser_id: Option<String>, installation_id: Option<String>, package_id: Option<String>,
    process_names: Vec<String>
});
model!(Detection { require_exclusive_owner: bool, signals: Vec<Signal> });
model!(Signal {
    id: String, root: Option<String>, artifact: Option<String>,
    family: EvidenceFamily, observe: ObservationKind
});
/// The initial conservative known-folder allowlist is per-user Local/Roaming AppData.
/// Registry roots name a selected owner's HKCU scope, never an ambient elevated hive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "base", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Root {
    /// Research-only installation slot. It grants no filesystem authority.
    ReviewedInstallation {
        id: String,
        relative: String,
        scope: Scope,
        owner: String,
    },
    LocalAppData {
        id: String,
        relative: String,
        scope: Scope,
        owner: String,
    },
    RoamingAppData {
        id: String,
        relative: String,
        scope: Scope,
        owner: String,
    },
    Registry {
        id: String,
        hive: RegistryHive,
        key: String,
        scope: Scope,
        owner: String,
    },
}
impl Root {
    pub fn id(&self) -> &str {
        match self {
            Self::ReviewedInstallation { id, .. }
            | Self::LocalAppData { id, .. }
            | Self::RoamingAppData { id, .. }
            | Self::Registry { id, .. } => id,
        }
    }
    pub fn relative(&self) -> &str {
        match self {
            Self::ReviewedInstallation { relative, .. }
            | Self::LocalAppData { relative, .. }
            | Self::RoamingAppData { relative, .. } => relative,
            Self::Registry { key, .. } => key,
        }
    }
    pub fn owner(&self) -> &str {
        match self {
            Self::ReviewedInstallation { owner, .. }
            | Self::LocalAppData { owner, .. }
            | Self::RoamingAppData { owner, .. }
            | Self::Registry { owner, .. } => owner,
        }
    }
    pub fn scope(&self) -> Scope {
        match self {
            Self::ReviewedInstallation { scope, .. }
            | Self::LocalAppData { scope, .. }
            | Self::RoamingAppData { scope, .. }
            | Self::Registry { scope, .. } => *scope,
        }
    }
}
model!(Profiles { root: String, directory_patterns: Vec<String>, metadata_adapter: Option<String>, root_profile: Option<bool> });
model!(SessionLocation {
    id: String, root: String, scope: Scope, relative: String, kind: ArtifactKind,
    observe: ObservationKind, ownership: Ownership, method: String,
    artifact_family: Option<String>, evidence: Option<Vec<EvidenceRef>>, confidence: Option<String>,
    name_prefix: Option<String>
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CleaningMethod {
    DeleteFileFamily {
        id: String,
        companions: Vec<String>,
        blockers: Vec<String>,
        effects: Option<Vec<String>>,
    },
    DeleteDirectoryFamily {
        id: String,
        blockers: Vec<String>,
        effects: Vec<String>,
        exclusions: Vec<String>,
    },
    DeleteRegistryTarget {
        id: String,
        blockers: Vec<String>,
        effects: Vec<String>,
    },
    LocalApiOperation {
        id: String,
        operation_id: String,
        blockers: Vec<String>,
        effects: Vec<String>,
    },
    ExceptionAdapter {
        id: String,
        adapter_id: String,
        blockers: Vec<String>,
        effects: Vec<String>,
    },
}
impl CleaningMethod {
    pub fn id(&self) -> &str {
        match self {
            Self::DeleteFileFamily { id, .. }
            | Self::DeleteDirectoryFamily { id, .. }
            | Self::DeleteRegistryTarget { id, .. }
            | Self::LocalApiOperation { id, .. }
            | Self::ExceptionAdapter { id, .. } => id,
        }
    }
    pub fn blockers(&self) -> &[String] {
        match self {
            Self::DeleteFileFamily { blockers, .. }
            | Self::DeleteDirectoryFamily { blockers, .. }
            | Self::DeleteRegistryTarget { blockers, .. }
            | Self::LocalApiOperation { blockers, .. }
            | Self::ExceptionAdapter { blockers, .. } => blockers,
        }
    }
    pub fn effects(&self) -> &[String] {
        match self {
            Self::DeleteFileFamily { effects, .. } => effects.as_deref().unwrap_or_default(),
            Self::DeleteDirectoryFamily { effects, .. }
            | Self::DeleteRegistryTarget { effects, .. }
            | Self::LocalApiOperation { effects, .. }
            | Self::ExceptionAdapter { effects, .. } => effects,
        }
    }
}
model!(Preservation {
    artifact_families: Vec<String>, shared_dependencies: Option<Vec<String>>
});
model!(TrueLogout {
    availability: Availability, surface: LogoutSurface, mechanism: String, evidence: Vec<EvidenceRef>
});
model!(EvidenceConfidence { level: Confidence, rationale: String, version_coverage: Option<String>, status: Option<String> });
model!(ExtensionPolicy { stores: Vec<String>, known: Vec<ExtensionRisk>, unknown: String });
model!(ExtensionRisk {
    id: String,
    name: String,
    flag: RiskFlag,
    source: String,
    accessed: String,
    confidence: String
});
model!(Evidence {
    id: String, dossier: String, source: Option<String>, revision: Option<String>,
    accessed: Option<String>, status: String
});

pub fn manifest_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(Manifest)).expect("schema is serializable")
}
