use crate::error::{MoveError, MoveResult};
use crate::types::{MoveTxPayload, MoveValue};

/// Move transaction payload parser
pub struct PayloadParser;

impl PayloadParser {
    /// Parse Move transaction payload.
    /// Opcode: 0x50-0x5F
    /// Format: [opcode:1][nonce:8 LE][module_addr:32][module_name:32][func_name_len:2][func_name:var][args_count:2][args:var]
    pub fn parse(payload: &[u8]) -> MoveResult<MoveTxPayload> {
        if payload.is_empty() {
            return Err(MoveError::InvalidFormat("Empty payload".into()));
        }

        let mut offset = 1; // Skip opcode byte (0x50-0x5F, already validated)

        // Parse sender sequence nonce (8 bytes, little-endian). This matches
        // mempool nonce extraction for 0x50/0x51 payloads.
        if offset + 8 > payload.len() {
            return Err(MoveError::InvalidFormat("Truncated nonce".into()));
        }
        let nonce = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
        offset += 8;

        // Parse module address (32 bytes)
        if offset + 32 > payload.len() {
            return Err(MoveError::InvalidFormat("Truncated module address".into()));
        }
        let mut module_address = [0u8; 32];
        module_address.copy_from_slice(&payload[offset..offset + 32]);
        offset += 32;

        // Parse module name (32 bytes)
        if offset + 32 > payload.len() {
            return Err(MoveError::InvalidFormat("Truncated module name".into()));
        }
        let module_name_bytes = &payload[offset..offset + 32];
        let module_name = String::from_utf8(module_name_bytes.to_vec())
            .map_err(|_| MoveError::InvalidFormat("Invalid module name UTF-8".into()))?
            .trim_end_matches('\0')
            .to_string();
        if module_name.is_empty() {
            return Err(MoveError::InvalidFormat("Empty module name".into()));
        }
        offset += 32;

        // Parse function name length (2 bytes, little-endian)
        if offset + 2 > payload.len() {
            return Err(MoveError::InvalidFormat("Truncated function name length".into()));
        }
        let func_name_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        // Parse function name
        if offset + func_name_len > payload.len() {
            return Err(MoveError::InvalidFormat("Truncated function name".into()));
        }
        let function_name = String::from_utf8(payload[offset..offset + func_name_len].to_vec())
            .map_err(|_| MoveError::InvalidFormat("Invalid function name UTF-8".into()))?;
        if function_name.is_empty() {
            return Err(MoveError::InvalidFormat("Empty function name".into()));
        }
        offset += func_name_len;

        // Parse argument count (2 bytes, little-endian)
        if offset + 2 > payload.len() {
            return Err(MoveError::InvalidFormat("Truncated arg count".into()));
        }
        let arg_count = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        // Parse arguments
        let mut args = Vec::new();
        for _ in 0..arg_count {
            let (arg, consumed) = Self::parse_value(&payload[offset..], 0)?;
            args.push(arg);
            offset += consumed;
        }
        if offset != payload.len() {
            return Err(MoveError::InvalidFormat("Trailing bytes after Move arguments".into()));
        }

        Ok(MoveTxPayload {
            nonce,
            module_address,
            module_name,
            function_name,
            args,
        })
    }

    /// Parse a single Move value
    fn parse_value(data: &[u8], depth: u32) -> MoveResult<(MoveValue, usize)> {
        if depth > 8 {
            return Err(MoveError::InvalidFormat("Value nesting too deep".into()));
        }
        if data.is_empty() {
            return Err(MoveError::InvalidBytecode("Empty value data".into()));
        }

        match data[0] {
            // Boolean (1 byte: type + 1 byte: value)
            0x01 => {
                if data.len() < 2 {
                    return Err(MoveError::InvalidBytecode("Truncated bool".into()));
                }
                Ok((MoveValue::Bool(data[1] != 0), 2))
            }
            // U8 (1 byte: type + 1 byte: value)
            0x02 => {
                if data.len() < 2 {
                    return Err(MoveError::InvalidBytecode("Truncated u8".into()));
                }
                Ok((MoveValue::U8(data[1]), 2))
            }
            // U64 (1 byte: type + 8 bytes: value)
            0x03 => {
                if data.len() < 9 {
                    return Err(MoveError::InvalidBytecode("Truncated u64".into()));
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[1..9]);
                Ok((MoveValue::U64(u64::from_le_bytes(bytes)), 9))
            }
            // U128 (1 byte: type + 16 bytes: value)
            0x04 => {
                if data.len() < 17 {
                    return Err(MoveError::InvalidBytecode("Truncated u128".into()));
                }
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&data[1..17]);
                Ok((MoveValue::U128(u128::from_le_bytes(bytes)), 17))
            }
            // Address (1 byte: type + 32 bytes: address)
            0x05 => {
                if data.len() < 33 {
                    return Err(MoveError::InvalidBytecode("Truncated address".into()));
                }
                let mut addr = [0u8; 32];
                addr.copy_from_slice(&data[1..33]);
                Ok((MoveValue::Address(addr), 33))
            }
            // Bytes vector (1 byte: type + 4 bytes: length + data)
            0x06 => {
                if data.len() < 5 {
                    return Err(MoveError::InvalidBytecode("Truncated bytes length".into()));
                }
                let len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                if data.len() < 5 + len {
                    return Err(MoveError::InvalidBytecode("Truncated bytes data".into()));
                }
                Ok((MoveValue::Bytes(data[5..5 + len].to_vec()), 5 + len))
            }
            // Vector (1 byte: type + 4 bytes: count + elements)
            0x07 => {
                if data.len() < 5 {
                    return Err(MoveError::InvalidBytecode("Truncated vector length".into()));
                }
                let count = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                let mut offset = 5;
                let mut elements = Vec::new();
                for _ in 0..count {
                    let (val, consumed) = Self::parse_value(&data[offset..], depth + 1)?;
                    elements.push(val);
                    offset += consumed;
                }
                Ok((MoveValue::Vector(elements), offset))
            }
            t => Err(MoveError::InvalidBytecode(format!("Unknown value type: 0x{:02x}", t))),
        }
    }
}

/// Move bytecode verifier
pub struct BytecodeVerifier;

impl BytecodeVerifier {
    pub fn verify_module(bytecode: &[u8]) -> MoveResult<()> {
        if bytecode.is_empty() {
            return Err(MoveError::VerificationFailed("Empty bytecode".into()));
        }

        // Basic sanity checks
        // In production, this would do full bytecode format validation
        if bytecode.len() > 8_192 {
            return Err(MoveError::VerificationFailed("Bytecode too large (max 8KB)".into()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_u64() {
        let mut payload = vec![0x50]; // Move VM opcode
        payload.extend_from_slice(&0u64.to_le_bytes()); // nonce
        payload.extend_from_slice(&[0u8; 32]); // module address
        let mut module_name = [0u8; 32];
        module_name[..5].copy_from_slice(b"Token");
        payload.extend_from_slice(&module_name);
        payload.extend_from_slice(&[4, 0]); // func name len = 4
        payload.extend_from_slice(b"mint");
        payload.extend_from_slice(&[1, 0]); // 1 arg
        payload.push(0x03); // u64 type
        payload.extend_from_slice(&100u64.to_le_bytes());

        let result = PayloadParser::parse(&payload).unwrap();
        assert_eq!(result.function_name, "mint");
        assert_eq!(result.args.len(), 1);
        assert_eq!(result.args[0].as_u64(), Some(100));
    }
}
