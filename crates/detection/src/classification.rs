use everyout_core_model::Category;
use everyout_providers::Ownership;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// Browser aliases already carry their canonical browser owner, never wrapper identity.
    pub owner: String,
    pub ownership: Ownership,
}
/// Rendering engines, Microsoft names and installer technology are not categories.
/// Conflicting owners remain unclassified even when one claim names a browser.
pub fn classify(claims: &[Claim]) -> Option<(String, Category)> {
    let first = claims.first()?;
    if first.owner.trim().is_empty() || claims.iter().any(|claim| claim.owner != first.owner) {
        return None;
    }
    let category = if claims
        .iter()
        .any(|c| c.ownership == Ownership::BrowserProfile)
    {
        Category::Browser
    } else if claims.iter().any(|c| {
        matches!(
            c.ownership,
            Ownership::SharedIdentity | Ownership::DeveloperTool
        )
    }) {
        Category::WindowsMicrosoftAndDevTools
    } else {
        Category::Application
    };
    Some((first.owner.clone(), category))
}
