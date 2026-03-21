//! CyberArmor AI Identity Control Plane Rust SDK.
//!
//! Provides policy evaluation, audit emission, and provider wrappers.

#![deny(missing_docs)]
#![warn(clippy::all)]

/// Internal audit event helpers.
pub(crate) mod audit;

/// SDK client.
pub mod client;

/// Configuration.
pub mod config;

/// Error types.
pub mod error;

/// Policy decision types.
pub mod policy;

/// AI provider wrappers.
pub mod providers;

// -------------------------------------------------------------------------
// Re-exports for ergonomic top-level imports
// -------------------------------------------------------------------------

pub use client::CyberArmorClient;
pub use config::{CyberArmorConfig, EnforceMode};
pub use error::CyberArmorError;
pub use policy::{DecisionType, PolicyDecision};
