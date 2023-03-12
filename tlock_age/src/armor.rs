use anyhow::anyhow;
use std::io::{Result, Write};

/// Writer that applies the age ASCII armor format.
pub struct ArmoredWriter<W: Write> {
    inner: age::armor::ArmoredWriter<W>,
}

impl<W: Write> ArmoredWriter<W> {
    /// Wraps the given output in an ArmoredWriter.
    pub fn wrap_output(w: W) -> anyhow::Result<Self> {
        let inner = age::armor::ArmoredWriter::wrap_output(w, age::armor::Format::AsciiArmor)
            .map_err(|e| anyhow!("error wrapping output {e}"))?;
        Ok(Self { inner })
    }

    /// Writes the end marker of the age file, if armoring was enabled.
    ///
    /// You MUST call finish when you are done writing, in order to `finish` the armoring process. Failing to call `finish` will result in a truncated file that that will fail to decrypt.
    pub fn finish(self) -> Result<W> {
        self.inner.finish()
    }
}

impl<W: Write> Write for ArmoredWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}
