//! # fints — Native Rust FinTS 3.0 PinTan Client
//!
//! A pure Rust implementation of the FinTS 3.0 (formerly HBCI) banking protocol
//! for German online banking.
//!
//! ## Architecture
//!
//! 1. **Protocol layer** (`protocol`): Typestate `Dialog<S>` — the dialog's auth
//!    state is in the type system. Business ops on an unauthenticated dialog = compile error.
//!
//! 2. **Workflow layer** (`workflow`): Bank workflows via the `BankOps` trait,
//!    dispatched by BLZ (`bank_ops`/`AnyBank`; DKB and a generic implementation).
//!
//! 3. **Flow layer** (`flow`): High-level `Flow` for connect → TAN confirm → fetch.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use fints::{Flow, UserId, Pin, ProductId};
//!
//! # async fn example() -> fints::Result<()> {
//! // BLZ 12030000 = DKB; any other registry BLZ works too.
//! let (mut flow, challenge) = Flow::initiate(
//!     "12030000", &UserId::new("user"), &Pin::new("pin"), &ProductId::new("PRODUCT_ID"),
//!     None, None, None,
//! ).await?;
//! // User confirms pushTAN in banking app...
//! let result = flow.confirm_and_fetch("DE123...", "BYLADEM...", 365).await?;
//! println!("Balance: {:?}, {} transactions", result.balance, result.transactions.len());
//! # Ok(())
//! # }
//! ```

// ── Infrastructure ──
pub mod banks;
pub mod banks_generated {
    include!(concat!(env!("OUT_DIR"), "/banks_generated.rs"));
}
pub mod error;
pub(crate) mod message;
pub(crate) mod parser;
pub(crate) mod segments;
pub(crate) mod serializer;
pub(crate) mod transport;
pub mod types;

// ── Tooling ──
pub mod debug;
pub mod audit;

// ── Architecture ──
pub mod protocol;
pub mod workflow;
pub mod flow;

// ═══════════════════════════════════════════════════════════════════════════════
// Re-exports
// ═══════════════════════════════════════════════════════════════════════════════

// Flow layer
pub use flow::{Flow, ChallengeInfo, SyncResult, FetchOptions};

// Workflow layer
pub use workflow::{BankOps, AnyBank, Dkb, GenericBank, bank_ops, bank_ops_with_config};
pub use workflow::{InitiateOutcome, InitiateResult, InitiateNoTanResult, FetchResult, FetchOpts};

// Protocol layer
pub use protocol::{
    Dialog, Response, TanChallenge, BankParams, Account,
    New, Synced, Open, TanPending,
    InitResult, SendResult, PollResult,
    BalanceResult, TransactionResult, TransactionPage,
    HoldingsResult, HoldingsPage,
};

// Domain types
pub use types::{
    AccountBalance, SepaAccount, Transaction, TransactionStatus, TanMethod,
    SecurityHolding, Isin, Wkn,
    Blz, UserId, Pin, SystemId, ProductId, DialogId, SecurityFunction,
    TaskReference, SegmentType, TanMediumName, TouchdownPoint, SegmentRef,
    Currency, Iban, Bic, TanProcess, ResponseCodeKind, ResponseCode,
    BankName, FinTSUrl, ChallengeText, HhdUcData, Mt940Data,
};
pub use error::{FinTSError, Result};
pub use banks::{BankConfig, all_banks, bank_by_blz};

// Debug / audit tooling
pub use debug::{DecodedMessage, DecodedSegment, VerbosityLevel, decode_message, format_decoded};
pub use audit::{AuditReport, Violation, ViolationSeverity, audit_client_message, audit_server_response};
