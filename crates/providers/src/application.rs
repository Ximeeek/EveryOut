//! Generic application scopes share the metadata-only manifest executor.
//! No runtime/framework hint grants ownership; callers supply reviewed installations.
use crate::{ApplicationKind, Manifest, Ownership, Root};
use everyout_core_model::{ArtifactKind, Category, Scope};

/// Enforce container boundaries independently of artifact labels and confirmations.
/// One root is one ownership scope; additional Local/Roaming roots use separate instances.
pub fn valid_scope(m: &Manifest) -> bool {
    let Some(kind) = m.application else {
        return false;
    };
    if kind == ApplicationKind::GamingLauncher {
        return crate::gaming::valid_scope(m);
    }
    if m.category != Category::Application
        || m.identity.browser_id.is_some()
        || m.roots.len() != 1
        || m.extensions.is_some()
        || !m
            .preserve
            .artifact_families
            .iter()
            .any(|f| f == "encryption-key-metadata")
    {
        return false;
    }
    let root = &m.roots[0];
    let path = root.relative().replace('\\', "/");
    let parts: Vec<_> = path.split('/').collect();
    let root_valid = match kind {
        ApplicationKind::Store => m.identity.package_id.as_ref().is_some_and(|pfn| {
            let Some((name, publisher)) = pfn.rsplit_once('_') else {
                return false;
            };
            !name.is_empty()
                && publisher.len() == 13
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                && publisher
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && matches!(root, Root::LocalAppData { .. })
                && path == format!("Packages/{pfn}")
                && m.profiles.is_none()
        }),
        ApplicationKind::GamingLauncher => false,
        ApplicationKind::ElectronCef | ApplicationKind::Webview2 => {
            m.identity.package_id.is_none()
                && m.identity
                    .installation_id
                    .as_ref()
                    .is_some_and(|id| !id.is_empty())
                && matches!(
                    root,
                    Root::LocalAppData { .. } | Root::RoamingAppData { .. }
                )
                && match kind {
                    ApplicationKind::ElectronCef => parts.len() == 1,
                    ApplicationKind::Webview2 => parts.len() == 2 && parts[1] == "EBWebView",
                    _ => false,
                }
                && !matches!(
                    parts[0].to_ascii_lowercase().as_str(),
                    "google"
                        | "microsoft"
                        | "mozilla"
                        | "bravesoftware"
                        | "opera software"
                        | "vivaldi"
                        | "packages"
                        | "edgewebview"
                )
                && m.profiles
                    .as_ref()
                    .is_none_or(|p| p.metadata_adapter.is_none())
        }
    };
    root_valid
        && m.session_locations.iter().all(|a| {
            if a.ownership != Ownership::Application {
                return false;
            }
            let path = a.relative.replace('\\', "/");
            if kind == ApplicationKind::Store {
                let Some((container, leaf)) = path.split_once('/') else {
                    return false;
                };
                a.scope != Scope::Profile
                    && matches!(container, "LocalState" | "LocalCache" | "RoamingState")
                    && (storage_target(leaf, a.kind)
                        || (leaf == "Session" && a.kind == ArtifactKind::Directory))
            } else {
                storage_target(&path, a.kind)
            }
        })
}

fn storage_target(path: &str, kind: ArtifactKind) -> bool {
    match kind {
        ArtifactKind::File => matches!(
            path,
            "Cookies" | "Network/Cookies" | "LocalStorage" | "SessionStorage"
        ),
        ArtifactKind::Directory => matches!(
            path,
            "Local Storage" | "Session Storage" | "IndexedDB" | "Service Worker" | "WebStorage"
        ),
        _ => false,
    }
}

/// Electron/CEF, WebView2 and Store are typed modes of the same confined executor.
#[cfg(windows)]
pub type ApplicationProvider<'a> = crate::executor::ManifestExecutor<'a>;
