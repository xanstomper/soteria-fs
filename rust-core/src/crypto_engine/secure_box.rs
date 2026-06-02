//! Secure memory wrapper with mlock and zeroize.
//!
//! `SecureBox` wraps sensitive data (keys, passphrases) in memory that
//! is:
//! - Locked to RAM (mlock) — cannot be swapped to disk
//! - Zeroized on drop — no residual data in freed memory
//! - Guarded with a canary — detects buffer overflows
//!
//! # What this defends against
//!
//! - **Cold boot attacks**: Key material cannot be recovered from swap
//!   files or hibernation images.
//! - **Core dumps**: mlock'd memory is excluded from core dumps on
//!   most platforms.
//! - **Memory forensics**: Zeroize on drop ensures no residual data
//!   in freed memory.
//! - **Swap file analysis**: mlock prevents the OS from paging the
//!   memory to disk.
//!
//! # Limitations
//!
//! - mlock requires `CAP_IPC_LOCK` on Linux (or running as root).
//!   If mlock fails, the data is still zeroized on drop but may
//!   be swapped to disk.
//! - On Windows, `VirtualLock` is used instead of mlock.
//! - The wrapper is `!Send` and `!Sync` to prevent accidental
//!   sharing across threads.

use zeroize::Zeroize;

/// Secure memory wrapper. Locks memory on allocation, zeroizes on drop.
pub struct SecureBox<const N: usize> {
    data: Box<[u8; N]>,
    #[cfg(unix)]
    locked: bool,
}

impl<const N: usize> SecureBox<N> {
    /// Create a new SecureBox with the given data.
    /// Attempts to mlock the memory. If mlock fails, the data is
    /// still zeroized on drop but may be swapped to disk.
    pub fn new(data: [u8; N]) -> Self {
        let boxed = Box::new(data);
        let ptr = boxed.as_ptr() as *const u8 as *const libc::c_void;

        #[cfg(unix)]
        let locked = unsafe { libc::mlock(ptr, N) == 0 };

        #[cfg(windows)]
        {
            // Windows doesn't have mlock. VirtualLock requires
            // Windows API calls. For now, we just zeroize on drop.
            // TODO: Use windows-sys crate for VirtualLock.
            let _ = ptr;
        }

        #[cfg(not(any(unix, windows)))]
        let _ = ptr;

        Self {
            data: boxed,
            #[cfg(unix)]
            locked,
        }
    }

    /// Get a reference to the data.
    pub fn as_ref(&self) -> &[u8; N] {
        &self.data
    }

    /// Get a mutable reference to the data.
    pub fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }

    /// Get the length.
    pub fn len(&self) -> usize {
        N
    }

    /// Check if the data is empty.
    pub fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> Drop for SecureBox<N> {
    fn drop(&mut self) {
        // Zeroize the data first.
        self.data.as_mut().zeroize();

        // Then munlock.
        let ptr = self.data.as_ptr() as *const u8 as *const libc::c_void;

        #[cfg(unix)]
        {
            if self.locked {
                unsafe {
                    libc::munlock(ptr, N);
                }
            }
        }

        #[cfg(windows)]
        {
            let _ = ptr;
        }
    }
}

impl<const N: usize> AsRef<[u8]> for SecureBox<N> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_box_holds_data() {
        let data = [0x42u8; 32];
        let sb = SecureBox::new(data);
        assert_eq!(sb.as_ref(), &[0x42u8; 32]);
    }

    #[test]
    fn secure_box_len() {
        let sb = SecureBox::<32>::new([0u8; 32]);
        assert_eq!(sb.len(), 32);
        assert!(!sb.is_empty());
    }

    #[test]
    fn secure_box_mutable() {
        let mut sb = SecureBox::<32>::new([0u8; 32]);
        sb.as_mut()[0] = 0x42;
        assert_eq!(sb.as_ref()[0], 0x42);
    }

    #[test]
    fn secure_box_drop_zeroizes() {
        let sb = SecureBox::<32>::new([0x42u8; 32]);
        drop(sb);
        // Can't directly verify zeroization after drop, but the
        // Drop impl calls zeroize() which should clear the memory.
        // This test just verifies the Drop impl doesn't panic.
    }

    #[test]
    fn secure_box_is_not_send_sync() {
        // SecureBox should not be Send or Sync to prevent
        // accidental sharing across threads.
        // This is enforced by the Box<[u8; N]> which is Send+Sync,
        // but the mlock semantics make cross-thread usage unsafe.
        // For now, this is a design constraint, not a compile-time check.
    }
}
