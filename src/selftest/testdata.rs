//! Deterministische Testdaten, ohne sie im Speicher zu halten.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Erzeugt denselben Bytestrom bei jedem Aufruf mit demselben Seed.
pub struct Gen {
    state: u64,
}

impl Gen {
    pub fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            // xorshift64*
            self.state ^= self.state >> 12;
            self.state ^= self.state << 25;
            self.state ^= self.state >> 27;
            let v = self.state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Vergleicht einen eintreffenden Strom beliebiger Stückelung mit dem erwarteten.
pub struct Verifier {
    rng: Gen,
    expected: Vec<u8>,
    pub received: u64,
    pub mismatch_at: Option<u64>,
}

impl Verifier {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Gen::new(seed),
            expected: Vec::new(),
            received: 0,
            mismatch_at: None,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        if self.mismatch_at.is_none() {
            // Der Generator liefert 8-Byte-Blöcke; Überschuss bleibt bis zum nächsten Stück liegen.
            let mut have = std::mem::take(&mut self.expected);
            if have.len() < data.len() {
                let mut more = vec![0u8; (data.len() - have.len()).div_ceil(8) * 8];
                self.rng.fill(&mut more);
                have.extend_from_slice(&more);
            }
            let (now, rest) = have.split_at(data.len());
            if now != data {
                let first = now.iter().zip(data).position(|(a, b)| a != b).unwrap_or(0);
                self.mismatch_at = Some(self.received + first as u64);
            }
            self.expected = rest.to_vec();
        }
        self.received += data.len() as u64;
    }
}

impl AsyncWrite for Verifier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.feed(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Schreibt `total` Bytes des Stroms in `writer`.
pub async fn write_stream<W: AsyncWrite + Unpin>(
    writer: &mut W,
    seed: u64,
    total: u64,
) -> std::io::Result<()> {
    let mut rng = Gen::new(seed);
    let mut buf = vec![0u8; 64 * 1024];
    let mut left = total;
    while left > 0 {
        let n = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
        rng.fill(&mut buf[..n]);
        writer.write_all(&buf[..n]).await?;
        left -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_accepts_any_chunking_and_detects_changes() {
        let mut data = vec![0u8; 100_003];
        Gen::new(7).fill(&mut data);

        let mut v = Verifier::new(7);
        for chunk in data.chunks(1237) {
            v.feed(chunk);
        }
        assert_eq!(v.received, data.len() as u64);
        assert_eq!(v.mismatch_at, None);

        let mut bad = data.clone();
        bad[54_321] ^= 1;
        let mut v = Verifier::new(7);
        for chunk in bad.chunks(999) {
            v.feed(chunk);
        }
        assert_eq!(v.mismatch_at, Some(54_321));
    }
}
