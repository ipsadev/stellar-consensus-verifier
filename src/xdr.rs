use crate::error::ScpError;

/// How deeply quorum sets may nest.
pub const MAX_QSET_DEPTH: u32 = 4;
/// The most validators a quorum set may name.
pub const MAX_QSET_VALIDATORS: usize = 1000;
/// A ceiling on any single variable-length field, so bad input cannot ask for unbounded memory.
pub const MAX_VAR_LEN: usize = 1 << 20;

/// What every decoding step in this crate returns.
pub type Result<T> = core::result::Result<T, ScpError>;

fn bad(what: &str) -> ScpError {
    ScpError::InvalidWire(what.into())
}

/// Reads Stellar's binary format, refusing anything malformed.
///
/// Every read is bounded and checked, so untrusted bytes cannot cause a panic
/// or an oversized allocation.
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Starts reading at the beginning of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// How many bytes have been read so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// How many bytes are left.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The exact bytes read since `start`.
    ///
    /// Used to capture the precise span a signature covers.
    pub fn slice_from(&self, start: usize) -> &'a [u8] {
        &self.buf[start..self.pos]
    }

    /// Confirms the whole input was consumed, rejecting trailing bytes.
    pub fn finish(&self) -> Result<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(bad("trailing bytes after decode"))
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| bad("length overflow"))?;

        if end > self.buf.len() {
            return Err(bad("unexpected end of input"));
        }

        let out = &self.buf[self.pos..end];

        self.pos = end;

        Ok(out)
    }

    /// Reads an unsigned 32-bit number.
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;

        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a signed 32-bit number.
    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    /// Reads an unsigned 64-bit number.
    pub fn u64(&mut self) -> Result<u64> {
        let hi = self.u32()? as u64;
        let lo = self.u32()? as u64;

        Ok((hi << 32) | lo)
    }

    /// Reads exactly `n` bytes, rejecting the padding if it is not zero.
    pub fn fixed(&mut self, n: usize) -> Result<&'a [u8]> {
        let out = self.take(n)?;
        let pad = (4 - (n % 4)) % 4;

        if pad > 0 {
            let padding = self.take(pad)?;

            if padding.iter().any(|b| *b != 0) {
                return Err(bad("non-zero XDR padding"));
            }
        }

        Ok(out)
    }

    /// Reads a length-prefixed field, refusing one larger than the input allows.
    pub fn var_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;

        if len > MAX_VAR_LEN || len > self.remaining() {
            return Err(bad("variable-length field too large"));
        }

        self.fixed(len)
    }

    /// Reads how many items follow, refusing a count that is too large to be real.
    pub fn vec_len(&mut self, max: usize) -> Result<usize> {
        let n = self.u32()? as usize;

        if n > max {
            return Err(bad("array longer than permitted"));
        }

        if n.saturating_mul(4) > self.remaining() {
            return Err(bad("array length exceeds remaining input"));
        }

        Ok(n)
    }

    /// Reads a 32-byte hash.
    pub fn fixed32(&mut self) -> Result<[u8; 32]> {
        let b = self.fixed(32)?;
        let mut out = [0u8; 32];

        out.copy_from_slice(b);

        Ok(out)
    }

    /// Reads a validator's public key.
    pub fn node_id(&mut self) -> Result<[u8; 32]> {
        match self.i32()? {
            0 => self.fixed32(),
            other => Err(bad(&alloc::format!("unsupported PublicKey type {other}"))),
        }
    }

    /// Reads a 64-byte signature.
    pub fn signature(&mut self) -> Result<[u8; 64]> {
        let b = self.var_bytes()?;

        if b.len() != 64 {
            return Err(bad("signature is not 64 bytes"));
        }

        let mut out = [0u8; 64];

        out.copy_from_slice(b);

        Ok(out)
    }
}

extern crate alloc;
