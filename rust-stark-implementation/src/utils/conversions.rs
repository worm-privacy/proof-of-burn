//! Type conversion utilities

use crate::Result;
use stwo::core::fields::m31::M31;

/// Convert bytes to M31 field element
pub fn bytes_to_field_element(bytes: &[u8]) -> Result<u32> {
    if bytes.is_empty() {
        return Ok(0);
    }
    
    // Take first 4 bytes and convert to u32
    let len = bytes.len().min(4);
    let mut arr = [0u8; 4];
    arr[..len].copy_from_slice(&bytes[..len]);
    
    let value = u32::from_be_bytes(arr);
    // Ensure value is within M31 field (2^31 - 1)
    let field_value = value % ((1u64 << 31) - 1) as u32;
    
    Ok(field_value)
}

/// Convert M31 field element to bytes
pub fn field_element_to_bytes(field: M31) -> [u8; 4] {
    field.0.to_be_bytes()
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim_start_matches("0x");
    if hex.len() % 2 != 0 {
        return Err(crate::ProofOfBurnError::InvalidInput { 
            reason: "Hex string must have even length".to_string() 
        });
    }
    
    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16)
            .map_err(|_| crate::ProofOfBurnError::InvalidInput { 
                reason: "Invalid hex character".to_string() 
            })?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    format!("0x{}", bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}
