//! FinTS message construction.
//!
//! Assembles a complete FinTS message from typed `Segment` values.
//! The security envelope (HNVSK/HNVSD/HNSHK/HNSHA) and message framing
//! (HNHBK/HNHBS) are constructed internally — never exposed as raw DEGs.

use crate::error::FinTSError;
use crate::parser::DEG;
use crate::protocol::{BankParams, Segment};
use crate::segments::builder::*;
use crate::serializer;

// ═══════════════════════════════════════════════════════════════════════════════
// Typed envelope — all parameters validated, no raw strings
// ═══════════════════════════════════════════════════════════════════════════════

/// Security context for message construction.
struct SecurityContext<'a> {
    dialog_id: &'a str,
    message_number: u16,
    blz: &'a str,
    user_id: &'a str,
    system_id: &'a str,
    pin: &'a str,
    tan: Option<&'a str>,
    security_function: &'a str,
}

/// Build a complete FinTS message from typed segments.
///
/// Structure:
/// ```text
/// HNHBK:1:3 (header with total size)
/// HNVSK:998:3 (encryption envelope)
/// HNVSD:999:1 (signed data, containing:)
///   HNSHK:2:4 (signature header)
///   <business segments from Segment enum>
///   HNSHA:N:2 (signature footer with PIN/TAN)
/// HNHBS:N+1:1 (message trailer)
/// ```
pub(crate) fn build_from_segments(
    ctx: &SecurityContext<'_>,
    segments: &[Segment],
    params: &BankParams,
) -> Result<Vec<u8>, FinTSError> {
    // Convert typed segments to raw DEGs
    let business_degs: Vec<Vec<DEG>> = segments.iter().map(|s| s.to_degs(params)).collect();
    build_message_raw(ctx, business_degs)
}

/// Build a complete FinTS message from raw DEGs (internal only).
/// Used by `build_from_segments` and the legacy `build_message` wrapper.
fn build_message_raw(
    ctx: &SecurityContext<'_>,
    business_segments: Vec<Vec<DEG>>,
) -> Result<Vec<u8>, FinTSError> {
    let security_reference = rand::random_range(1_000_000u32..10_000_000u32);

    let mut inner_segment_number: u16 = 2;

    // HNSHK (signature header)
    let hnshk_seg = hnshk(
        inner_segment_number,
        ctx.security_function,
        security_reference,
        ctx.blz,
        ctx.user_id,
        ctx.system_id,
    );
    inner_segment_number += 1;

    // Number business segments sequentially
    let mut numbered_business: Vec<Vec<DEG>> = Vec::new();
    for mut seg in business_segments {
        if let Some(header) = seg.first_mut() {
            if header.0.len() >= 2 {
                header.0[1] = crate::parser::DataElement::Text(inner_segment_number.to_string());
            }
        }
        numbered_business.push(seg);
        inner_segment_number += 1;
    }

    // HNSHA (signature footer)
    let hnsha_seg = hnsha(inner_segment_number, security_reference, ctx.pin, ctx.tan);
    inner_segment_number += 1;

    // Serialize inner segments
    let mut inner_bytes = Vec::new();
    inner_bytes.extend(serializer::serialize_segment(&hnshk_seg)?);
    for seg in &numbered_business {
        inner_bytes.extend(serializer::serialize_segment(seg)?);
    }
    inner_bytes.extend(serializer::serialize_segment(&hnsha_seg)?);

    // Build outer envelope
    let hnvsk_seg = hnvsk(ctx.blz, ctx.user_id, ctx.system_id, ctx.security_function);
    let hnvsd_seg = hnvsd(&inner_bytes);
    let trailer_number = inner_segment_number;
    let hnhbs_seg = hnhbs(trailer_number, ctx.message_number);

    // Serialize body (everything after HNHBK)
    let mut body_bytes = Vec::new();
    body_bytes.extend(serializer::serialize_segment(&hnvsk_seg)?);
    body_bytes.extend(serializer::serialize_segment(&hnvsd_seg)?);
    body_bytes.extend(serializer::serialize_segment(&hnhbs_seg)?);

    // Compute total size with placeholder header
    let hnhbk_placeholder = hnhbk(0, ctx.dialog_id, ctx.message_number);
    let header_bytes = serializer::serialize_segment(&hnhbk_placeholder)?;
    let total_size = header_bytes.len() + body_bytes.len();

    // Rebuild header with correct size
    let hnhbk_final = hnhbk(total_size as u32, ctx.dialog_id, ctx.message_number);
    let header_final = serializer::serialize_segment(&hnhbk_final)?;
    assert_eq!(
        header_final.len(),
        header_bytes.len(),
        "Header size changed after size update!"
    );

    let mut message = Vec::with_capacity(total_size);
    message.extend(header_final);
    message.extend(body_bytes);
    Ok(message)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public API for protocol.rs
// ═══════════════════════════════════════════════════════════════════════════════

use crate::types::{Blz, DialogId, Pin, SecurityFunction, SystemId, UserId};

/// Build a message from typed segments (no TAN).
pub(crate) fn build_message_from_typed(
    dialog_id: &DialogId,
    message_number: u16,
    blz: &Blz,
    user_id: &UserId,
    system_id: &SystemId,
    pin: &Pin,
    security_function: &SecurityFunction,
    segments: &[Segment],
    params: &BankParams,
) -> Result<Vec<u8>, FinTSError> {
    let ctx = SecurityContext {
        dialog_id: dialog_id.as_str(),
        message_number,
        blz: blz.as_str(),
        user_id: user_id.as_str(),
        system_id: system_id.as_str(),
        pin: pin.as_str(),
        tan: None,
        security_function: security_function.as_str(),
    };
    build_from_segments(&ctx, segments, params)
}

/// Build a message from typed segments WITH a TAN value.
pub(crate) fn build_message_from_typed_with_tan(
    dialog_id: &DialogId,
    message_number: u16,
    blz: &Blz,
    user_id: &UserId,
    system_id: &SystemId,
    pin: &Pin,
    tan: &str,
    security_function: &SecurityFunction,
    segments: &[Segment],
    params: &BankParams,
) -> Result<Vec<u8>, FinTSError> {
    let ctx = SecurityContext {
        dialog_id: dialog_id.as_str(),
        message_number,
        blz: blz.as_str(),
        user_id: user_id.as_str(),
        system_id: system_id.as_str(),
        pin: pin.as_str(),
        tan: Some(tan),
        security_function: security_function.as_str(),
    };
    build_from_segments(&ctx, segments, params)
}

/// Build a dialog-end message.
pub(crate) fn build_end_message(
    dialog_id: &DialogId,
    message_number: u16,
    blz: &Blz,
    user_id: &UserId,
    system_id: &SystemId,
    pin: &Pin,
    security_function: &SecurityFunction,
    params: &BankParams,
) -> Result<Vec<u8>, FinTSError> {
    let segments = [Segment::End {
        dialog_id: dialog_id.clone(),
    }];
    build_message_from_typed(
        dialog_id,
        message_number,
        blz,
        user_id,
        system_id,
        pin,
        security_function,
        &segments,
        params,
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// Legacy wrapper (for tests only)
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a message from raw DEGs. Used only by unit tests.
#[allow(dead_code)]
pub(crate) fn build_message(
    dialog_id: &str,
    message_number: u16,
    blz: &str,
    user_id: &str,
    system_id: &str,
    pin: &str,
    tan: Option<&str>,
    security_function: &str,
    business_segments: Vec<Vec<DEG>>,
) -> Result<Vec<u8>, FinTSError> {
    let ctx = SecurityContext {
        dialog_id,
        message_number,
        blz,
        user_id,
        system_id,
        pin,
        tan,
        security_function,
    };
    build_message_raw(&ctx, business_segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_message_structure() {
        let msg = build_message(
            "0",
            1,
            "12030000",
            "testuser",
            "0",
            "12345",
            None,
            "999",
            vec![hkidn(0, "12030000", "testuser", "0")],
        )
        .unwrap();

        let raw = String::from_utf8_lossy(&msg);
        assert!(raw.starts_with("HNHBK:1:3+"));
        assert!(raw.contains("HNVSK:998:3+"));
        assert!(raw.contains("HNVSD:999:1+"));
        assert!(raw.ends_with('\''));

        let segments = crate::parser::parse_message(&msg).unwrap();
        assert_eq!(segments[0].segment_type(), "HNHBK");
        assert_eq!(segments[1].segment_type(), "HNVSK");
        assert_eq!(segments[2].segment_type(), "HNVSD");
        assert_eq!(segments.last().unwrap().segment_type(), "HNHBS");
    }

    #[test]
    fn test_message_size_in_header() {
        let msg = build_message(
            "0",
            1,
            "12030000",
            "testuser",
            "0",
            "12345",
            None,
            "999",
            vec![hkidn(0, "12030000", "testuser", "0")],
        )
        .unwrap();

        let segments = crate::parser::parse_message(&msg).unwrap();
        let size_str = segments[0].deg(1).get_str(0);
        let size: usize = size_str.parse().unwrap();
        assert_eq!(size, msg.len());
    }
}
