//! RLP encoding utilities



/// RLP encoder for Ethereum data structures
pub struct RlpEncoder;

impl RlpEncoder {
    pub fn new() -> Self {
        Self
    }
    
    /// Encode bytes as RLP
    pub fn encode_bytes(&self, data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            // Single byte < 0x80 is encoded as itself
            data.to_vec()
        } else if data.len() < 56 {
            // Short string: 0x80 + length, then data
            let mut result = vec![0x80 + data.len() as u8];
            result.extend_from_slice(data);
            result
        } else {
            // Long string: 0xb7 + length of length, then length, then data
            let len_bytes = self.encode_length(data.len());
            let mut result = vec![0xb7 + len_bytes.len() as u8];
            result.extend_from_slice(&len_bytes);
            result.extend_from_slice(data);
            result
        }
    }
    
    /// Encode list as RLP
    pub fn encode_list(&self, items: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for item in items {
            payload.extend_from_slice(item);
        }
        
        if payload.len() < 56 {
            // Short list: 0xc0 + length, then payload
            let mut result = vec![0xc0 + payload.len() as u8];
            result.extend_from_slice(&payload);
            result
        } else {
            // Long list: 0xf7 + length of length, then length, then payload
            let len_bytes = self.encode_length(payload.len());
            let mut result = vec![0xf7 + len_bytes.len() as u8];
            result.extend_from_slice(&len_bytes);
            result.extend_from_slice(&payload);
            result
        }
    }
    
    /// Encode account state for MPT
    pub fn encode_account(&self, nonce: u64, balance: u64, storage_root: &[u8; 32], code_hash: &[u8; 32]) -> Vec<u8> {
        let nonce_bytes = self.encode_bytes(&self.encode_integer(nonce));
        let balance_bytes = self.encode_bytes(&self.encode_integer(balance));
        let storage_bytes = self.encode_bytes(storage_root);
        let code_bytes = self.encode_bytes(code_hash);
        
        self.encode_list(&[nonce_bytes, balance_bytes, storage_bytes, code_bytes])
    }
    
    /// Encode integer (remove leading zeros)
    fn encode_integer(&self, value: u64) -> Vec<u8> {
        if value == 0 {
            return vec![0x80]; // Empty string encoding for zero
        }
        
        let bytes = value.to_be_bytes();
        // Remove leading zeros
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        bytes[start..].to_vec()
    }
    
    /// Encode length as big-endian bytes
    fn encode_length(&self, length: usize) -> Vec<u8> {
        if length == 0 {
            return vec![];
        }
        
        let bytes = length.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        bytes[start..].to_vec()
    }
}

impl Default for RlpEncoder {
    fn default() -> Self {
        Self::new()
    }
}
