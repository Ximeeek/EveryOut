//! Discovery identifies possible owners, never authentication or deletion scope.
//! S8 is pending: scores are unverified policy, and all heuristics remain unchecked.
#![forbid(unsafe_code)]

pub mod classification;
pub mod heuristic;
#[cfg(windows)]
pub mod scanner;

use everyout_core_model::{Category, Confidence, DetectionOrigin};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detection {
    pub id: String,
    pub origin: DetectionOrigin,
    pub confidence: Confidence,
    pub points: Option<u8>,
    pub signals: Vec<String>,
    pub observations: Vec<SignalObservation>,
    pub owner: Option<String>,
    pub category: Option<Category>,
    pub selected: bool,
    /// Discovery alone never supplies a reviewed executable plan.
    pub executable: bool,
    pub aliases: Vec<String>,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignalObservation {
    pub id: String,
    /// Unknown access/type is separate from absence.
    pub present: Option<bool>,
    pub size: Option<u64>,
}
#[derive(Debug, Default, Serialize)]
pub struct ScanReport {
    pub known: Vec<Detection>,
    /// Includes high heuristics until S8 passes, always initially unchecked.
    pub candidates: Vec<Detection>,
    pub coverage: Vec<String>,
}
