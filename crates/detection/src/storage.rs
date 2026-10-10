//! Bounded, metadata-only storage discovery independent of provider catalogs.
//! A layout or cache-like name establishes a candidate, never a deletion target.
use crate::{heuristic::excluded, StorageDiscovery};
use everyout_platform_windows::{
    inventory::{InstalledInventory, InventorySource},
    AllowedRoot, KnownFolder, RootResolver,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_DIRECTORIES: usize = 2_000;
const MAX_DEPTH: usize = 6;
const MAX_QUEUE: usize = 2_000;
const MAX_CANDIDATES: usize = 500;

// Never descend into databases, web content, downloads or installed dependency trees.
fn leaf(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "cache"
            | "caches"
            | "code cache"
            | "gpucache"
            | "shadercache"
            | "dawncache"
            | "grshadercache"
            | "diskcache"
            | "cacheddata"
            | "local storage"
            | "session storage"
            | "indexeddb"
            | "service worker"
            | "network"
            | "downloads"
            | "logs"
            | "crashes"
            | "crashpad"
            | "node_modules"
            | "resources"
            | "extensions"
    )
}

fn signals(children: &[(String, bool)], network_cookies: bool) -> Vec<String> {
    let names: BTreeMap<_, _> = children
        .iter()
        .map(|(name, directory)| (name.to_ascii_lowercase(), *directory))
        .collect();
    let dir = |name: &str| names.get(name) == Some(&true);
    let file = |name: &str| names.get(name) == Some(&false);
    let mut result = Vec::new();
    if [
        "cache",
        "caches",
        "code cache",
        "gpucache",
        "shadercache",
        "diskcache",
        "cacheddata",
    ]
    .iter()
    .any(|name| dir(name))
    {
        result.push("cache-directory-name".into());
    }
    let cookies = file("cookies") || network_cookies;
    let web_stores = ["local storage", "session storage", "indexeddb"]
        .iter()
        .filter(|name| dir(name))
        .count();
    if (web_stores >= 2 && cookies) || web_stores == 3 {
        result.push("chromium-storage-cluster".into());
    }
    if file("cookies.sqlite") && (file("places.sqlite") || file("prefs.js")) {
        result.push("mozilla-storage-cluster".into());
    }
    result
}

struct Pending {
    relative: String,
    label: String,
    group: String,
    depth: usize,
}

/// Names are used only as local UI hints. Returned diagnostics use fixed codes;
/// no file payload, shortcut arguments or arbitrary registry values are read.
pub fn discover(
    resolver: &dyn RootResolver,
    inventory: &InstalledInventory,
    cancelled: &dyn Fn() -> bool,
) -> (Vec<StorageDiscovery>, Vec<String>) {
    let (discoveries, coverage, _) = discover_with_roots(resolver, inventory, cancelled);
    (discoveries, coverage)
}

/// Read-only observation hints using the existing bounded scanner. No ownership
/// or authentication authority accompanies the retained root capabilities.
pub fn discover_with_roots(
    resolver: &dyn RootResolver,
    inventory: &InstalledInventory,
    cancelled: &dyn Fn() -> bool,
) -> (Vec<StorageDiscovery>, Vec<String>, Vec<AllowedRoot>) {
    let mut observation_roots = Vec::new();
    let mut coverage = Vec::new();
    let mut groups = BTreeMap::<String, StorageDiscovery>::new();
    let mut visited = 0;
    for (folder, scope) in [
        (KnownFolder::LocalAppData, "local"),
        (KnownFolder::RoamingAppData, "roaming"),
    ] {
        if cancelled() {
            coverage.push("cancelled".into());
            break;
        }
        let Ok(root) = resolver.resolve(folder) else {
            coverage.push(format!("storage-{scope}-root-unavailable"));
            continue;
        };
        let mut queue = VecDeque::new();
        match root.discovery_children() {
            Ok((children, omitted)) => {
                if omitted {
                    coverage.push("storage-entries-omitted".into());
                }
                for (index, (name, directory)) in children.into_iter().enumerate() {
                    if !directory || excluded(&name) || leaf(&name) {
                        continue;
                    }
                    enqueue(
                        &mut queue,
                        Pending {
                            relative: name.clone(),
                            label: name,
                            group: format!("storage-{scope}-{index}"),
                            depth: 1,
                        },
                        &mut coverage,
                    );
                }
            }
            Err(_) => coverage.push(format!("storage-{scope}-enumeration-incomplete")),
        }
        if folder == KnownFolder::LocalAppData {
            for (index, registration) in inventory.registrations.iter().enumerate() {
                let Some(family) = &registration.package_family else {
                    continue;
                };
                if registration.source != InventorySource::Package
                    || excluded(family)
                    || family.contains(['/', '\\'])
                {
                    continue;
                }
                // Only independently registered containers, never all of Packages.
                enqueue(
                    &mut queue,
                    Pending {
                        relative: format!("Packages/{family}"),
                        label: registration.name.clone(),
                        group: format!("storage-package-{index}"),
                        depth: 1,
                    },
                    &mut coverage,
                );
            }
        }
        let mut scope_visited = 0;
        while let Some(pending) = queue.pop_front() {
            if cancelled() {
                coverage.push("cancelled".into());
                break;
            }
            if visited >= MAX_DIRECTORIES {
                coverage.push("storage-directory-budget-exhausted".into());
                break;
            }
            // One busy Local tree must not consume the entire Roaming budget.
            if scope_visited >= MAX_DIRECTORIES / 2 {
                coverage.push(format!("storage-{scope}-directory-budget-exhausted"));
                break;
            }
            visited += 1;
            scope_visited += 1;
            let Ok(directory) = root.discovery_descendant(&pending.relative) else {
                coverage.push("storage-directory-unavailable".into());
                continue;
            };
            if inspect(&directory, pending, &mut queue, &mut groups, &mut coverage)
                && observation_roots.len() < MAX_CANDIDATES
            {
                observation_roots.push(directory);
            }
        }
        if visited >= MAX_DIRECTORIES {
            break;
        }
    }
    coverage.extend([
        "storage-custom-and-portable-locations-unobserved".into(),
        "storage-layout-does-not-prove-logout-or-deletion-scope".into(),
    ]);
    coverage.sort();
    coverage.dedup();
    (groups.into_values().collect(), coverage, observation_roots)
}

fn enqueue(queue: &mut VecDeque<Pending>, pending: Pending, coverage: &mut Vec<String>) {
    if queue.len() < MAX_QUEUE {
        queue.push_back(pending);
    } else {
        note(coverage, "storage-queue-budget-exhausted");
    }
}

fn note(coverage: &mut Vec<String>, code: &str) {
    if !coverage.iter().any(|existing| existing == code) {
        coverage.push(code.into());
    }
}

fn inspect(
    directory: &AllowedRoot,
    pending: Pending,
    queue: &mut VecDeque<Pending>,
    groups: &mut BTreeMap<String, StorageDiscovery>,
    coverage: &mut Vec<String>,
) -> bool {
    let Ok((children, omitted)) = directory.discovery_children() else {
        coverage.push("storage-enumeration-incomplete".into());
        return false;
    };
    if omitted {
        coverage.push("storage-entries-omitted".into());
    }
    let network_cookies = match directory
        .path("Network/Cookies")
        .and_then(|path| path.probe_shallow())
    {
        Ok(metadata) => metadata.exists && !metadata.is_directory,
        Err(_) => {
            note(coverage, "storage-cookie-metadata-incomplete");
            false
        }
    };
    let observed = signals(&children, network_cookies);
    let candidate = !observed.is_empty();
    if !observed.is_empty() {
        if groups.len() < MAX_CANDIDATES || groups.contains_key(&pending.group) {
            let discovery =
                groups
                    .entry(pending.group.clone())
                    .or_insert_with(|| StorageDiscovery {
                        id: pending.group.clone(),
                        label: pending.label.clone(),
                        signals: vec![],
                        locations: 0,
                        limitations: vec![
                            "folder-label-is-not-application-identity".into(),
                            "exclusive-owner-unresolved".into(),
                            "no-authentication-or-cleaning-scope-proof".into(),
                        ],
                    });
            discovery.locations += 1;
            let mut combined: BTreeSet<_> = discovery.signals.iter().cloned().collect();
            combined.extend(observed);
            discovery.signals = combined.into_iter().collect();
        } else {
            coverage.push("storage-candidate-budget-exhausted".into());
        }
    }
    for (name, is_directory) in children {
        if !is_directory || excluded(&name) || leaf(&name) {
            continue;
        }
        if pending.depth >= MAX_DEPTH {
            note(coverage, "storage-depth-budget-exhausted");
            continue;
        }
        enqueue(
            queue,
            Pending {
                relative: format!("{}/{name}", pending.relative),
                label: pending.label.clone(),
                group: pending.group.clone(),
                depth: pending.depth + 1,
            },
            coverage,
        );
    }
    candidate
}
