//! Bank registry: known German banks with their FinTS endpoint URLs.
//!
//! Banks are identified solely by their BLZ (Bankleitzahl). There is no
//! separate `id` field — the BLZ is the canonical identifier.

use serde::{Deserialize, Serialize};

use crate::types::{BankName, Bic, Blz, FinTSUrl};

/// Configuration for a known bank.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankConfig {
    pub name: BankName,
    pub blz: Blz,
    pub bic: Bic,
    pub url: FinTSUrl,
}

impl BankConfig {
    /// Create a new BankConfig.
    pub fn new(
        name: impl Into<String>,
        blz: impl Into<String>,
        bic: impl Into<String>,
        url: impl Into<String>,
    ) -> Self {
        Self {
            name: BankName::new(name),
            blz: Blz::new(blz),
            bic: Bic::new(bic),
            url: FinTSUrl::new(url),
        }
    }
}

/// Get all known banks with FinTS PIN/TAN access.
pub fn all_banks() -> Vec<BankConfig> {
    crate::banks_generated::generated_all_banks()
}

/// Look up a bank by its BLZ (bank code).
pub fn bank_by_blz(blz: &str) -> Option<BankConfig> {
    crate::banks_generated::generated_bank_by_blz(blz)
}
