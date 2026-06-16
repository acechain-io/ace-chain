//! Bitcoin Script interpreter.
//!
//! A stack-based virtual machine implementing Bitcoin Script opcodes
//! for P2PKH, P2SH, multi-sig, and UTXO-model transactions.
//!
//! The interpreter operates on a stack of byte vectors and evaluates
//! scripts left-to-right. Conditional execution (IF/ELSE/ENDIF) is
//! supported via a condition stack.

use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature as EcdsaSignature, VerifyingKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Bitcoin Script opcodes (subset relevant for ACE BVM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    // ── Constants ──
    Op0 = 0x00,
    // Push N bytes (0x01–0x4b = push 1–75 bytes directly)
    OpPushData1 = 0x4c,
    OpPushData2 = 0x4d,
    Op1Negate = 0x4f,
    Op1 = 0x51,
    Op2 = 0x52,
    Op3 = 0x53,
    Op4 = 0x54,
    Op5 = 0x55,
    Op6 = 0x56,
    Op7 = 0x57,
    Op8 = 0x58,
    Op9 = 0x59,
    Op10 = 0x5a,
    Op11 = 0x5b,
    Op12 = 0x5c,
    Op13 = 0x5d,
    Op14 = 0x5e,
    Op15 = 0x5f,
    Op16 = 0x60,

    // ── Flow control ──
    OpNop = 0x61,
    OpIf = 0x63,
    OpNotIf = 0x64,
    OpElse = 0x67,
    OpEndIf = 0x68,
    OpVerify = 0x69,
    OpReturn = 0x6a,

    // ── Stack operations ──
    Op2Drop = 0x6d,
    Op2Dup = 0x6e,
    OpIfDup = 0x73,
    OpDepth = 0x74,
    OpDrop = 0x75,
    OpDup = 0x76,
    OpNip = 0x77,
    OpOver = 0x78,
    OpPick = 0x79,
    OpRoll = 0x7a,
    OpRot = 0x7b,
    OpSwap = 0x7c,
    OpTuck = 0x7d,
    OpSize = 0x82,

    // ── Bitwise logic ──
    OpEqual = 0x87,
    OpEqualVerify = 0x88,

    // ── Arithmetic ──
    Op1Add = 0x8b,
    Op1Sub = 0x8c,
    OpNegate = 0x8f,
    OpAbs = 0x90,
    OpNot = 0x91,
    Op0NotEqual = 0x92,
    OpAdd = 0x93,
    OpSub = 0x94,
    OpBoolAnd = 0x9a,
    OpBoolOr = 0x9b,
    OpNumEqual = 0x9c,
    OpNumEqualVerify = 0x9d,
    OpNumNotEqual = 0x9e,
    OpLessThan = 0x9f,
    OpGreaterThan = 0xa0,
    OpLessThanOrEqual = 0xa1,
    OpGreaterThanOrEqual = 0xa2,
    OpMin = 0xa3,
    OpMax = 0xa4,
    OpWithin = 0xa5,

    // ── Crypto ──
    OpSha256 = 0xa8,
    OpHash160 = 0xa9,
    OpHash256 = 0xaa,
    OpCheckSig = 0xac,
    OpCheckSigVerify = 0xad,
    OpCheckMultiSig = 0xae,
    OpCheckMultiSigVerify = 0xaf,

    // ── Lock-time ──
    OpCheckLockTimeVerify = 0xb1,
    OpCheckSequenceVerify = 0xb2,
}

impl OpCode {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Op0),
            0x4c => Some(Self::OpPushData1),
            0x4d => Some(Self::OpPushData2),
            0x4f => Some(Self::Op1Negate),
            0x51 => Some(Self::Op1),
            0x52 => Some(Self::Op2),
            0x53 => Some(Self::Op3),
            0x54 => Some(Self::Op4),
            0x55 => Some(Self::Op5),
            0x56 => Some(Self::Op6),
            0x57 => Some(Self::Op7),
            0x58 => Some(Self::Op8),
            0x59 => Some(Self::Op9),
            0x5a => Some(Self::Op10),
            0x5b => Some(Self::Op11),
            0x5c => Some(Self::Op12),
            0x5d => Some(Self::Op13),
            0x5e => Some(Self::Op14),
            0x5f => Some(Self::Op15),
            0x60 => Some(Self::Op16),
            0x61 => Some(Self::OpNop),
            0x63 => Some(Self::OpIf),
            0x64 => Some(Self::OpNotIf),
            0x67 => Some(Self::OpElse),
            0x68 => Some(Self::OpEndIf),
            0x69 => Some(Self::OpVerify),
            0x6a => Some(Self::OpReturn),
            0x6d => Some(Self::Op2Drop),
            0x6e => Some(Self::Op2Dup),
            0x73 => Some(Self::OpIfDup),
            0x74 => Some(Self::OpDepth),
            0x75 => Some(Self::OpDrop),
            0x76 => Some(Self::OpDup),
            0x77 => Some(Self::OpNip),
            0x78 => Some(Self::OpOver),
            0x79 => Some(Self::OpPick),
            0x7a => Some(Self::OpRoll),
            0x7b => Some(Self::OpRot),
            0x7c => Some(Self::OpSwap),
            0x7d => Some(Self::OpTuck),
            0x82 => Some(Self::OpSize),
            0x87 => Some(Self::OpEqual),
            0x88 => Some(Self::OpEqualVerify),
            0x8b => Some(Self::Op1Add),
            0x8c => Some(Self::Op1Sub),
            0x8f => Some(Self::OpNegate),
            0x90 => Some(Self::OpAbs),
            0x91 => Some(Self::OpNot),
            0x92 => Some(Self::Op0NotEqual),
            0x93 => Some(Self::OpAdd),
            0x94 => Some(Self::OpSub),
            0x9a => Some(Self::OpBoolAnd),
            0x9b => Some(Self::OpBoolOr),
            0x9c => Some(Self::OpNumEqual),
            0x9d => Some(Self::OpNumEqualVerify),
            0x9e => Some(Self::OpNumNotEqual),
            0x9f => Some(Self::OpLessThan),
            0xa0 => Some(Self::OpGreaterThan),
            0xa1 => Some(Self::OpLessThanOrEqual),
            0xa2 => Some(Self::OpGreaterThanOrEqual),
            0xa3 => Some(Self::OpMin),
            0xa4 => Some(Self::OpMax),
            0xa5 => Some(Self::OpWithin),
            0xa8 => Some(Self::OpSha256),
            0xa9 => Some(Self::OpHash160),
            0xaa => Some(Self::OpHash256),
            0xac => Some(Self::OpCheckSig),
            0xad => Some(Self::OpCheckSigVerify),
            0xae => Some(Self::OpCheckMultiSig),
            0xaf => Some(Self::OpCheckMultiSigVerify),
            0xb1 => Some(Self::OpCheckLockTimeVerify),
            0xb2 => Some(Self::OpCheckSequenceVerify),
            _ => None,
        }
    }
}

/// Script execution error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptError {
    StackUnderflow,
    InvalidOpcode(u8),
    ScriptTooLarge,
    PushDataOutOfBounds,
    VerifyFailed,
    OpReturnEncountered,
    UnbalancedConditional,
    InvalidNumber,
    DivisionByZero,
    CheckSigFailed,
    CheckMultiSigFailed,
    MaxStackSizeExceeded,
    MaxOpsExceeded,
    ElementSizeExceeded,
    SigopsLimitExceeded,
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StackUnderflow => write!(f, "stack underflow"),
            Self::InvalidOpcode(op) => write!(f, "invalid opcode: 0x{op:02x}"),
            Self::ScriptTooLarge => write!(f, "script exceeds max size (10,000 bytes)"),
            Self::PushDataOutOfBounds => write!(f, "push data extends beyond script"),
            Self::VerifyFailed => write!(f, "OP_VERIFY failed"),
            Self::OpReturnEncountered => write!(f, "OP_RETURN encountered"),
            Self::UnbalancedConditional => write!(f, "unbalanced IF/ELSE/ENDIF"),
            Self::InvalidNumber => write!(f, "invalid script number"),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::CheckSigFailed => write!(f, "signature verification failed"),
            Self::CheckMultiSigFailed => write!(f, "multi-sig verification failed"),
            Self::MaxStackSizeExceeded => write!(f, "stack size exceeds 1000 elements"),
            Self::MaxOpsExceeded => write!(f, "exceeded 201 non-push opcode limit"),
            Self::ElementSizeExceeded => write!(f, "push data exceeds 520 bytes"),
            Self::SigopsLimitExceeded => write!(f, "exceeded sigops limit"),
        }
    }
}

/// Maximum script size in bytes.
const MAX_SCRIPT_SIZE: usize = 10_000;
/// Maximum stack depth.
const MAX_STACK_SIZE: usize = 1_000;
/// Maximum non-push opcodes per script.
const MAX_OPS_PER_SCRIPT: usize = 201;
/// Maximum size of a single stack element (Bitcoin consensus rule).
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// Maximum signature operations per script evaluation.
const MAX_SIGOPS_PER_SCRIPT: usize = 80;

/// Bitcoin Script interpreter.
///
/// Evaluates a script against a stack, following Bitcoin's consensus rules
/// for the supported opcode subset.
pub struct ScriptInterpreter {
    stack: Vec<Vec<u8>>,
    /// Condition stack for IF/ELSE/ENDIF nesting.
    cond_stack: Vec<bool>,
    /// Number of non-push opcodes executed (capped at 201).
    op_count: usize,
    /// Signature operations consumed (capped at MAX_SIGOPS_PER_SCRIPT).
    sigop_count: usize,
    /// Signature hash for OP_CHECKSIG verification.
    /// Set by the caller before script evaluation.
    pub sig_hash: [u8; 32],
}

impl ScriptInterpreter {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            cond_stack: Vec::new(),
            op_count: 0,
            sigop_count: 0,
            sig_hash: [0u8; 32],
        }
    }

    /// Push an item onto the stack (used to pre-load scriptSig data).
    pub fn push(&mut self, data: Vec<u8>) {
        self.stack.push(data);
    }

    /// Get the current stack (for result inspection).
    pub fn stack(&self) -> &[Vec<u8>] {
        &self.stack
    }

    /// Check if the top of stack is truthy (non-zero, non-negative-zero).
    pub fn top_is_true(&self) -> bool {
        match self.stack.last() {
            None => false,
            Some(v) => is_true(v),
        }
    }

    /// Returns true if currently executing (all conditions on cond_stack are true).
    fn executing(&self) -> bool {
        self.cond_stack.iter().all(|&c| c)
    }

    /// Evaluate a script. Returns Ok(true) if the script succeeds
    /// (top of stack is truthy after execution).
    pub fn eval(&mut self, script: &[u8]) -> Result<bool, ScriptError> {
        if script.len() > MAX_SCRIPT_SIZE {
            return Err(ScriptError::ScriptTooLarge);
        }

        let mut pc = 0;

        while pc < script.len() {
            let byte = script[pc];
            pc += 1;

            // Direct push: 0x01..=0x4b push N bytes
            if (0x01..=0x4b).contains(&byte) {
                let n = byte as usize;
                if pc + n > script.len() {
                    return Err(ScriptError::PushDataOutOfBounds);
                }
                if self.executing() {
                    if n > MAX_SCRIPT_ELEMENT_SIZE {
                        return Err(ScriptError::ElementSizeExceeded);
                    }
                    self.stack.push(script[pc..pc + n].to_vec());
                    self.check_stack_size()?;
                }
                pc += n;
                continue;
            }

            // Try to parse as a known opcode
            let opcode = match OpCode::from_byte(byte) {
                Some(op) => op,
                None => {
                    if self.executing() {
                        return Err(ScriptError::InvalidOpcode(byte));
                    }
                    continue;
                }
            };

            // Flow control opcodes must always be processed
            match opcode {
                OpCode::OpIf | OpCode::OpNotIf | OpCode::OpElse | OpCode::OpEndIf => {
                    self.execute_flow_control(opcode)?;
                    continue;
                }
                _ => {}
            }

            // Skip non-flow-control opcodes when not executing
            if !self.executing() {
                continue;
            }

            // Count non-push opcodes
            if byte > 0x60 {
                self.op_count += 1;
                if self.op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::MaxOpsExceeded);
                }
            }

            match opcode {
                // ── Constants ──
                OpCode::Op0 => {
                    self.stack.push(vec![]);
                }
                OpCode::Op1Negate => {
                    self.stack.push(encode_num(-1));
                }
                OpCode::Op1
                | OpCode::Op2
                | OpCode::Op3
                | OpCode::Op4
                | OpCode::Op5
                | OpCode::Op6
                | OpCode::Op7
                | OpCode::Op8
                | OpCode::Op9
                | OpCode::Op10
                | OpCode::Op11
                | OpCode::Op12
                | OpCode::Op13
                | OpCode::Op14
                | OpCode::Op15
                | OpCode::Op16 => {
                    let n = (byte - 0x50) as i64;
                    self.stack.push(encode_num(n));
                }
                OpCode::OpPushData1 => {
                    if pc >= script.len() {
                        return Err(ScriptError::PushDataOutOfBounds);
                    }
                    let n = script[pc] as usize;
                    pc += 1;
                    if pc + n > script.len() {
                        return Err(ScriptError::PushDataOutOfBounds);
                    }
                    if n > MAX_SCRIPT_ELEMENT_SIZE {
                        return Err(ScriptError::ElementSizeExceeded);
                    }
                    self.stack.push(script[pc..pc + n].to_vec());
                    self.check_stack_size()?;
                    pc += n;
                }
                OpCode::OpPushData2 => {
                    if pc + 2 > script.len() {
                        return Err(ScriptError::PushDataOutOfBounds);
                    }
                    let n = u16::from_le_bytes([script[pc], script[pc + 1]]) as usize;
                    pc += 2;
                    if pc + n > script.len() {
                        return Err(ScriptError::PushDataOutOfBounds);
                    }
                    if n > MAX_SCRIPT_ELEMENT_SIZE {
                        return Err(ScriptError::ElementSizeExceeded);
                    }
                    self.stack.push(script[pc..pc + n].to_vec());
                    self.check_stack_size()?;
                    pc += n;
                }

                // ── Flow control (non-conditional) ──
                OpCode::OpNop => {}
                OpCode::OpVerify => {
                    let top = self.pop()?;
                    if !is_true(&top) {
                        return Err(ScriptError::VerifyFailed);
                    }
                }
                OpCode::OpReturn => {
                    return Err(ScriptError::OpReturnEncountered);
                }

                // ── Stack manipulation ──
                OpCode::OpDup => {
                    let top = self.peek(0)?;
                    self.stack.push(top);
                    self.check_stack_size()?;
                }
                OpCode::OpDrop => {
                    self.pop()?;
                }
                OpCode::Op2Drop => {
                    self.pop()?;
                    self.pop()?;
                }
                OpCode::Op2Dup => {
                    let a = self.peek(1)?;
                    let b = self.peek(0)?;
                    self.stack.push(a);
                    self.stack.push(b);
                    self.check_stack_size()?;
                }
                OpCode::OpSwap => {
                    let len = self.stack.len();
                    if len < 2 {
                        return Err(ScriptError::StackUnderflow);
                    }
                    self.stack.swap(len - 1, len - 2);
                }
                OpCode::OpOver => {
                    let item = self.peek(1)?;
                    self.stack.push(item);
                    self.check_stack_size()?;
                }
                OpCode::OpRot => {
                    let len = self.stack.len();
                    if len < 3 {
                        return Err(ScriptError::StackUnderflow);
                    }
                    let item = self.stack.remove(len - 3);
                    self.stack.push(item);
                }
                OpCode::OpNip => {
                    let len = self.stack.len();
                    if len < 2 {
                        return Err(ScriptError::StackUnderflow);
                    }
                    self.stack.remove(len - 2);
                }
                OpCode::OpTuck => {
                    let len = self.stack.len();
                    if len < 2 {
                        return Err(ScriptError::StackUnderflow);
                    }
                    let top = self.stack[len - 1].clone();
                    self.stack.insert(len - 2, top);
                    self.check_stack_size()?;
                }
                OpCode::OpIfDup => {
                    let top = self.peek(0)?;
                    if is_true(&top) {
                        self.stack.push(top);
                        self.check_stack_size()?;
                    }
                }
                OpCode::OpDepth => {
                    self.stack.push(encode_num(self.stack.len() as i64));
                    self.check_stack_size()?;
                }
                OpCode::OpPick => {
                    let n = decode_num(&self.pop()?)? as usize;
                    let item = self.peek(n)?;
                    self.stack.push(item);
                    self.check_stack_size()?;
                }
                OpCode::OpRoll => {
                    let n = decode_num(&self.pop()?)? as usize;
                    let len = self.stack.len();
                    if n >= len {
                        return Err(ScriptError::StackUnderflow);
                    }
                    let item = self.stack.remove(len - 1 - n);
                    self.stack.push(item);
                }
                OpCode::OpSize => {
                    let top = self.peek(0)?;
                    self.stack.push(encode_num(top.len() as i64));
                    self.check_stack_size()?;
                }

                // ── Bitwise/equality ──
                OpCode::OpEqual => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.stack.push(if a == b { vec![1] } else { vec![] });
                }
                OpCode::OpEqualVerify => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    if a != b {
                        return Err(ScriptError::VerifyFailed);
                    }
                }

                // ── Arithmetic ──
                OpCode::Op1Add => {
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(encode_num(a + 1));
                }
                OpCode::Op1Sub => {
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(encode_num(a - 1));
                }
                OpCode::OpNegate => {
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(encode_num(-a));
                }
                OpCode::OpAbs => {
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(encode_num(a.abs()));
                }
                OpCode::OpAdd => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(encode_num(a + b));
                }
                OpCode::OpSub => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(encode_num(a - b));
                }
                OpCode::OpNot => {
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(if a == 0 { vec![1] } else { vec![] });
                }
                OpCode::Op0NotEqual => {
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(if a != 0 { vec![1] } else { vec![] });
                }
                OpCode::OpBoolAnd => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack
                        .push(if a != 0 && b != 0 { vec![1] } else { vec![] });
                }
                OpCode::OpBoolOr => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack
                        .push(if a != 0 || b != 0 { vec![1] } else { vec![] });
                }
                OpCode::OpNumEqual => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(if a == b { vec![1] } else { vec![] });
                }
                OpCode::OpNumEqualVerify => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    if a != b {
                        return Err(ScriptError::VerifyFailed);
                    }
                }
                OpCode::OpNumNotEqual => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(if a != b { vec![1] } else { vec![] });
                }
                OpCode::OpLessThan => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(if a < b { vec![1] } else { vec![] });
                }
                OpCode::OpGreaterThan => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(if a > b { vec![1] } else { vec![] });
                }
                OpCode::OpLessThanOrEqual => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(if a <= b { vec![1] } else { vec![] });
                }
                OpCode::OpGreaterThanOrEqual => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(if a >= b { vec![1] } else { vec![] });
                }
                OpCode::OpMin => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(encode_num(a.min(b)));
                }
                OpCode::OpMax => {
                    let b = decode_num(&self.pop()?)?;
                    let a = decode_num(&self.pop()?)?;
                    self.stack.push(encode_num(a.max(b)));
                }
                OpCode::OpWithin => {
                    let max = decode_num(&self.pop()?)?;
                    let min = decode_num(&self.pop()?)?;
                    let x = decode_num(&self.pop()?)?;
                    self.stack
                        .push(if x >= min && x < max { vec![1] } else { vec![] });
                }

                // ── Cryptographic ──
                OpCode::OpSha256 => {
                    let data = self.pop()?;
                    let hash = sha256(&data);
                    self.stack.push(hash.to_vec());
                }
                OpCode::OpHash160 => {
                    let data = self.pop()?;
                    let hash = hash160_real(&data);
                    self.stack.push(hash.to_vec());
                }
                OpCode::OpHash256 => {
                    let data = self.pop()?;
                    let hash = hash256(&data);
                    self.stack.push(hash.to_vec());
                }
                OpCode::OpCheckSig => {
                    self.count_sigops(1)?;
                    let pubkey = self.pop()?;
                    let sig = self.pop()?;
                    let valid = verify_ecdsa_signature(&sig, &pubkey, &self.sig_hash);
                    self.stack.push(if valid { vec![1] } else { vec![] });
                }
                OpCode::OpCheckSigVerify => {
                    self.count_sigops(1)?;
                    let pubkey = self.pop()?;
                    let sig = self.pop()?;
                    if !verify_ecdsa_signature(&sig, &pubkey, &self.sig_hash) {
                        return Err(ScriptError::CheckSigFailed);
                    }
                }
                OpCode::OpCheckMultiSig => {
                    self.execute_checkmultisig(false)?;
                }
                OpCode::OpCheckMultiSigVerify => {
                    self.execute_checkmultisig(true)?;
                }

                // ── Lock-time (treated as NOP on ACE — verified by consensus) ──
                OpCode::OpCheckLockTimeVerify | OpCode::OpCheckSequenceVerify => {
                    // Like Bitcoin's BIP 65/112: verify is done at consensus level,
                    // script just ensures the stack value is valid.
                    let _val = self.peek(0)?;
                }

                // Flow control handled above
                OpCode::OpIf | OpCode::OpNotIf | OpCode::OpElse | OpCode::OpEndIf => {
                    unreachable!()
                }
            }
        }

        if !self.cond_stack.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }

        Ok(self.top_is_true())
    }

    fn execute_flow_control(&mut self, opcode: OpCode) -> Result<(), ScriptError> {
        match opcode {
            OpCode::OpIf => {
                if self.executing() {
                    let top = self.pop()?;
                    self.cond_stack.push(is_true(&top));
                } else {
                    self.cond_stack.push(false);
                }
            }
            OpCode::OpNotIf => {
                if self.executing() {
                    let top = self.pop()?;
                    self.cond_stack.push(!is_true(&top));
                } else {
                    self.cond_stack.push(false);
                }
            }
            OpCode::OpElse => {
                if self.cond_stack.is_empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                let last = self.cond_stack.len() - 1;
                // Only flip the innermost condition if all outer conditions are true
                let outer_executing = if last == 0 {
                    true
                } else {
                    self.cond_stack[..last].iter().all(|&c| c)
                };
                if outer_executing {
                    self.cond_stack[last] = !self.cond_stack[last];
                }
            }
            OpCode::OpEndIf => {
                if self.cond_stack.is_empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                self.cond_stack.pop();
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn execute_checkmultisig(&mut self, verify: bool) -> Result<(), ScriptError> {
        let n = decode_num(&self.pop()?)? as usize;
        if n > 20 {
            return Err(ScriptError::CheckMultiSigFailed);
        }
        // Each pubkey in the multisig counts as one sigop
        self.count_sigops(n)?;

        let mut pubkeys = Vec::with_capacity(n);
        for _ in 0..n {
            pubkeys.push(self.pop()?);
        }

        let m = decode_num(&self.pop()?)? as usize;
        if m > n {
            return Err(ScriptError::CheckMultiSigFailed);
        }
        let mut sigs = Vec::with_capacity(m);
        for _ in 0..m {
            sigs.push(self.pop()?);
        }

        // Bitcoin's off-by-one: pop an extra unused value
        let _ = self.pop()?;

        // Verify m-of-n: each sig must match a pubkey, in order
        let mut key_idx = 0;
        let mut valid_count = 0;
        for sig in &sigs {
            while key_idx < pubkeys.len() {
                if verify_ecdsa_signature(sig, &pubkeys[key_idx], &self.sig_hash) {
                    valid_count += 1;
                    key_idx += 1;
                    break;
                }
                key_idx += 1;
            }
        }

        let success = valid_count >= m;
        if verify && !success {
            return Err(ScriptError::CheckMultiSigFailed);
        }
        self.stack.push(if success { vec![1] } else { vec![] });
        Ok(())
    }

    /// Count signature operations and enforce the per-script sigops limit.
    fn count_sigops(&mut self, n: usize) -> Result<(), ScriptError> {
        self.sigop_count += n;
        if self.sigop_count > MAX_SIGOPS_PER_SCRIPT {
            return Err(ScriptError::SigopsLimitExceeded);
        }
        Ok(())
    }

    fn pop(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.stack.pop().ok_or(ScriptError::StackUnderflow)
    }

    fn peek(&self, depth: usize) -> Result<Vec<u8>, ScriptError> {
        let len = self.stack.len();
        if depth >= len {
            return Err(ScriptError::StackUnderflow);
        }
        Ok(self.stack[len - 1 - depth].clone())
    }

    fn check_stack_size(&self) -> Result<(), ScriptError> {
        if self.stack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::MaxStackSizeExceeded);
        }
        Ok(())
    }
}

impl Default for ScriptInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Script number encoding (Bitcoin's CScriptNum) ──

/// Encode an i64 as a Bitcoin script number.
pub fn encode_num(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }

    let negative = n < 0;
    let mut abs = if negative { -n } else { n } as u64;
    let mut result = Vec::new();

    while abs > 0 {
        result.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    // If the most significant byte has its high bit set, add a sign byte.
    if result.last().unwrap() & 0x80 != 0 {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = result.len() - 1;
        result[last] |= 0x80;
    }

    result
}

/// Decode a Bitcoin script number from bytes.
pub fn decode_num(data: &[u8]) -> Result<i64, ScriptError> {
    if data.is_empty() {
        return Ok(0);
    }
    if data.len() > 4 {
        return Err(ScriptError::InvalidNumber);
    }

    let negative = data.last().unwrap() & 0x80 != 0;
    let mut result: i64 = 0;

    for (i, &byte) in data.iter().enumerate() {
        result |= (byte as i64) << (8 * i);
    }

    if negative {
        // Clear the sign bit
        result &= !(0x80i64 << (8 * (data.len() - 1)));
        result = -result;
    }

    Ok(result)
}

/// Check if a script stack element is "true" (non-zero).
fn is_true(data: &[u8]) -> bool {
    for (i, &byte) in data.iter().enumerate() {
        if byte != 0 {
            // Negative zero: last byte is 0x80, rest are 0x00
            if i == data.len() - 1 && byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

fn hash256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Real RIPEMD160(SHA256(data)) — Bitcoin-compatible HASH160.
fn hash160_real(data: &[u8]) -> [u8; 20] {
    let sha = sha256(data);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha);
    let result = ripemd.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// Verify an ECDSA secp256k1 signature against a sighash.
///
/// Accepts DER-encoded signatures (with optional trailing sighash byte)
/// and compressed (33-byte) or uncompressed (65-byte) SEC1 public keys.
fn verify_ecdsa_signature(sig: &[u8], pubkey: &[u8], sig_hash: &[u8; 32]) -> bool {
    if sig.is_empty() || pubkey.is_empty() {
        return false;
    }
    // Strip trailing sighash type byte (e.g. SIGHASH_ALL = 0x01)
    let sig_bytes = if sig.len() > 1 {
        &sig[..sig.len() - 1]
    } else {
        sig
    };

    let Ok(vk) = VerifyingKey::from_sec1_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = EcdsaSignature::from_der(sig_bytes) else {
        return false;
    };
    vk.verify_prehash(sig_hash, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_num() {
        for n in [-100, -1, 0, 1, 42, 127, 128, 255, 256, 1000, -1000] {
            let encoded = encode_num(n);
            let decoded = decode_num(&encoded).unwrap();
            assert_eq!(decoded, n, "roundtrip failed for {n}");
        }
    }

    #[test]
    fn test_op_add() {
        let mut interp = ScriptInterpreter::new();
        // Script: OP_1 OP_2 OP_ADD => stack should have [3]
        let script = vec![0x51, 0x52, 0x93];
        let result = interp.eval(&script).unwrap();
        assert!(result);
        assert_eq!(decode_num(&interp.stack()[0]).unwrap(), 3);
    }

    #[test]
    fn test_op_dup_equalverify() {
        let mut interp = ScriptInterpreter::new();
        // Push 0x42, DUP, EQUALVERIFY => empty stack (verify passes)
        let script = vec![0x01, 0x42, 0x76, 0x88];
        // EQUALVERIFY consumes both, stack is empty, but verify passed
        let result = interp.eval(&script).unwrap();
        // Stack is empty after EQUALVERIFY, so top_is_true is false
        assert!(!result);
        assert!(interp.stack().is_empty());
    }

    #[test]
    fn test_op_sha256() {
        let mut interp = ScriptInterpreter::new();
        // Push "hello", OP_SHA256
        let hello = b"hello";
        let mut script = vec![hello.len() as u8];
        script.extend_from_slice(hello);
        script.push(0xa8); // OP_SHA256
        let result = interp.eval(&script).unwrap();
        assert!(result);
        assert_eq!(interp.stack()[0].len(), 32);
        assert_eq!(interp.stack()[0], sha256(hello).to_vec());
    }

    #[test]
    fn test_op_if_else_endif() {
        let mut interp = ScriptInterpreter::new();
        // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let script = vec![0x51, 0x63, 0x52, 0x67, 0x53, 0x68];
        let result = interp.eval(&script).unwrap();
        assert!(result);
        assert_eq!(decode_num(&interp.stack()[0]).unwrap(), 2);
    }

    #[test]
    fn test_op_if_false_branch() {
        let mut interp = ScriptInterpreter::new();
        // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let script = vec![0x00, 0x63, 0x52, 0x67, 0x53, 0x68];
        let result = interp.eval(&script).unwrap();
        assert!(result);
        assert_eq!(decode_num(&interp.stack()[0]).unwrap(), 3);
    }

    #[test]
    fn test_op_return_fails() {
        let mut interp = ScriptInterpreter::new();
        let script = vec![0x6a]; // OP_RETURN
        let err = interp.eval(&script).unwrap_err();
        assert_eq!(err, ScriptError::OpReturnEncountered);
    }

    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

    /// Helper: generate a real secp256k1 keypair, sign the sighash, return
    /// (DER sig || sighash_type, compressed pubkey, sighash).
    fn make_ecdsa_sig(msg: &[u8]) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let sk = SigningKey::from_slice(&sha256(msg)).unwrap();
        let vk = sk.verifying_key();
        let sig_hash = sha256(msg);
        let (ecdsa_sig, _) = sk.sign_prehash(&sig_hash).unwrap();
        let mut der = ecdsa_sig.to_der().as_bytes().to_vec();
        der.push(0x01); // SIGHASH_ALL
        (der, vk.to_sec1_bytes().to_vec(), sig_hash)
    }

    #[test]
    fn test_checksig() {
        let (sig, pubkey, sig_hash) = make_ecdsa_sig(b"test_tx");

        let mut interp = ScriptInterpreter::new();
        interp.sig_hash = sig_hash;
        interp.push(sig);
        interp.push(pubkey);
        let script = vec![0xac]; // OP_CHECKSIG
        let result = interp.eval(&script).unwrap();
        assert!(result);
    }

    #[test]
    fn test_checksig_wrong_key_fails() {
        let (sig, _pubkey, sig_hash) = make_ecdsa_sig(b"test_tx");
        let (_sig2, wrong_pubkey, _) = make_ecdsa_sig(b"other_key");

        let mut interp = ScriptInterpreter::new();
        interp.sig_hash = sig_hash;
        interp.push(sig);
        interp.push(wrong_pubkey);
        let script = vec![0xac]; // OP_CHECKSIG
        let result = interp.eval(&script).unwrap();
        assert!(!result); // should push false
    }

    #[test]
    fn test_p2pkh_pattern() {
        let (sig, pubkey, sig_hash) = make_ecdsa_sig(b"tx_data");
        let pubkey_hash = hash160_real(&pubkey);

        let mut interp = ScriptInterpreter::new();
        interp.sig_hash = sig_hash;

        // Pre-load scriptSig: <sig> <pubkey>
        interp.push(sig);
        interp.push(pubkey);

        // scriptPubKey: OP_DUP OP_HASH160 <20 bytes hash> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = vec![0x76, 0xa9, 20]; // OP_DUP OP_HASH160 PUSH20
        script.extend_from_slice(&pubkey_hash);
        script.push(0x88); // OP_EQUALVERIFY
        script.push(0xac); // OP_CHECKSIG

        let result = interp.eval(&script).unwrap();
        assert!(result);
    }

    #[test]
    fn test_new_arithmetic_opcodes() {
        let mut interp = ScriptInterpreter::new();
        // OP_5 OP_1ADD => 6
        let script = vec![0x55, 0x8b];
        interp.eval(&script).unwrap();
        assert_eq!(decode_num(interp.stack().last().unwrap()).unwrap(), 6);

        let mut interp = ScriptInterpreter::new();
        // OP_5 OP_1SUB => 4
        let script = vec![0x55, 0x8c];
        interp.eval(&script).unwrap();
        assert_eq!(decode_num(interp.stack().last().unwrap()).unwrap(), 4);

        let mut interp = ScriptInterpreter::new();
        // OP_3 OP_NEGATE => -3
        let script = vec![0x53, 0x8f];
        interp.eval(&script).unwrap();
        assert_eq!(decode_num(interp.stack().last().unwrap()).unwrap(), -3);

        let mut interp = ScriptInterpreter::new();
        // OP_1NEGATE OP_ABS => 1
        let script = vec![0x4f, 0x90];
        interp.eval(&script).unwrap();
        assert_eq!(decode_num(interp.stack().last().unwrap()).unwrap(), 1);

        let mut interp = ScriptInterpreter::new();
        // OP_1 OP_1 OP_BOOLAND => 1
        let script = vec![0x51, 0x51, 0x9a];
        interp.eval(&script).unwrap();
        assert_eq!(decode_num(interp.stack().last().unwrap()).unwrap(), 1);

        let mut interp = ScriptInterpreter::new();
        // OP_0 OP_1 OP_BOOLOR => 1
        let script = vec![0x00, 0x51, 0x9b];
        interp.eval(&script).unwrap();
        assert_eq!(decode_num(interp.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_new_stack_opcodes() {
        // OP_DEPTH
        let mut interp = ScriptInterpreter::new();
        interp.push(vec![1]);
        interp.push(vec![2]);
        let script = vec![0x74]; // OP_DEPTH
        interp.eval(&script).unwrap();
        assert_eq!(decode_num(interp.stack().last().unwrap()).unwrap(), 2);

        // OP_SIZE
        let mut interp = ScriptInterpreter::new();
        interp.push(vec![0xaa, 0xbb, 0xcc]);
        let script = vec![0x82]; // OP_SIZE
        interp.eval(&script).unwrap();
        assert_eq!(decode_num(interp.stack().last().unwrap()).unwrap(), 3);

        // OP_PICK
        let mut interp = ScriptInterpreter::new();
        interp.push(encode_num(10));
        interp.push(encode_num(20));
        interp.push(encode_num(30));
        let script = vec![0x52, 0x79]; // OP_2 OP_PICK => copies item at depth 2 (= 10)
        interp.eval(&script).unwrap();
        assert_eq!(decode_num(interp.stack().last().unwrap()).unwrap(), 10);

        // OP_ROLL
        let mut interp = ScriptInterpreter::new();
        interp.push(encode_num(10));
        interp.push(encode_num(20));
        interp.push(encode_num(30));
        let script = vec![0x52, 0x7a]; // OP_2 OP_ROLL => moves item at depth 2 to top
        interp.eval(&script).unwrap();
        assert_eq!(decode_num(interp.stack().last().unwrap()).unwrap(), 10);
        assert_eq!(interp.stack().len(), 3); // ROLL doesn't increase stack size

        // OP_2DROP
        let mut interp = ScriptInterpreter::new();
        interp.push(vec![1]);
        interp.push(vec![2]);
        interp.push(vec![3]);
        let script = vec![0x6d]; // OP_2DROP
        interp.eval(&script).unwrap();
        assert_eq!(interp.stack().len(), 1);
    }

    #[test]
    fn test_element_size_limit() {
        let mut interp = ScriptInterpreter::new();
        // PUSHDATA2 with 521 bytes (exceeds 520 limit)
        let mut script = vec![0x4d];
        script.extend_from_slice(&521u16.to_le_bytes());
        script.extend(vec![0u8; 521]);
        let err = interp.eval(&script).unwrap_err();
        assert_eq!(err, ScriptError::ElementSizeExceeded);
    }

    #[test]
    fn test_sigops_limit() {
        let mut interp = ScriptInterpreter::new();
        // 81 consecutive OP_CHECKSIG (exceeds MAX_SIGOPS_PER_SCRIPT = 80)
        let mut script = Vec::new();
        for _ in 0..81 {
            script.push(0x00); // push empty sig
            script.push(0x00); // push empty pubkey
            script.push(0xac); // OP_CHECKSIG
        }
        let err = interp.eval(&script).unwrap_err();
        assert_eq!(err, ScriptError::SigopsLimitExceeded);
    }
}
