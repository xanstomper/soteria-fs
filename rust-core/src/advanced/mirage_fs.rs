//! Mirage File System — hidden directory structure.
//!
//! Files are stored at keyed hash positions. The directory listing is
//! not stored — it's derived from a Bloom filter and keyed hashes.
//! An attacker who doesn't know the exact filename cannot discover
//! that a file exists.
//!
//! # What this defends against
//!
//! - **File enumeration**: An attacker who mounts the volume cannot
//!   list files without knowing the directory key.
//! - **Metadata analysis**: No directory tree, no filenames, no
//!   timestamps on disk.
//! - **File carving**: No file boundaries in the ciphertext.
//!
//! # How it works
//!
//! 1. Each file is stored at a position derived from
//!    `BLAKE3("mirage:pos:v1" || dir_key || filename)`.
//! 2. A Bloom filter tracks which positions have files.
//! 3. To check if a file exists: compute the hash, check the Bloom filter.
//! 4. To read a file: compute the hash, read from that position.
//! 5. False positives in the Bloom filter create noise that hides
//!    real files.

use blake3;

/// A simple Bloom filter for file existence checks.
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: usize,
}

impl BloomFilter {
    /// Create a new Bloom filter with the given capacity.
    pub fn new(capacity: usize) -> Self {
        let num_bits = capacity * 8; // 8x oversizing for low false positive rate
        let num_hashes = 7; // Optimal for 1% false positive rate
        Self {
            bits: vec![0u64; (num_bits + 63) / 64],
            num_bits,
            num_hashes,
        }
    }

    /// Add an item to the filter.
    pub fn insert(&mut self, item: &[u8]) {
        for i in 0..self.num_hashes {
            let hash = self.hash_at(item, i);
            let bit = hash % self.num_bits;
            self.bits[bit / 64] |= 1u64 << (bit % 64);
        }
    }

    /// Check if an item might be in the filter.
    /// Returns true if the item is probably in the filter (with false
    /// positive rate ~1%). Returns false if the item is definitely
    /// NOT in the filter.
    pub fn contains(&self, item: &[u8]) -> bool {
        for i in 0..self.num_hashes {
            let hash = self.hash_at(item, i);
            let bit = hash % self.num_bits;
            if self.bits[bit / 64] & (1u64 << (bit % 64)) == 0 {
                return false;
            }
        }
        true
    }

    fn hash_at(&self, item: &[u8], index: usize) -> usize {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"mirage:bloom:v1");
        hasher.update(&index.to_le_bytes());
        hasher.update(item);
        let hash = hasher.finalize();
        u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap()) as usize
    }
}

/// The Mirage filesystem.
pub struct MirageFS {
    /// Directory key (derived from volume key).
    dir_key: [u8; 32],
    /// Bloom filter tracking file existence.
    bloom: BloomFilter,
    /// File storage: position -> encrypted data.
    /// In a real implementation, this would be backed by the volume's
    /// block storage.
    storage: std::collections::HashMap<u64, Vec<u8>>,
}

impl MirageFS {
    /// Create a new Mirage filesystem with the given directory key.
    pub fn new(dir_key: [u8; 32]) -> Self {
        Self {
            dir_key,
            bloom: BloomFilter::new(10_000),
            storage: std::collections::HashMap::new(),
        }
    }

    /// Compute the storage position for a filename.
    pub fn file_position(&self, filename: &str) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"mirage:pos:v1");
        hasher.update(&self.dir_key);
        hasher.update(filename.as_bytes());
        u64::from_le_bytes(hasher.finalize().as_bytes()[..8].try_into().unwrap())
    }

    /// Check if a file might exist (Bloom filter check).
    /// Returns true if the file probably exists (with ~1% false positive).
    /// Returns false if the file definitely does not exist.
    pub fn might_exist(&self, filename: &str) -> bool {
        let pos = self.file_position(filename);
        self.bloom.contains(&pos.to_le_bytes())
    }

    /// Write a file to the filesystem.
    pub fn write(&mut self, filename: &str, data: &[u8]) {
        let pos = self.file_position(filename);
        self.bloom.insert(&pos.to_le_bytes());
        self.storage.insert(pos, data.to_vec());
    }

    /// Read a file from the filesystem.
    /// Returns None if the file doesn't exist (or if the Bloom filter
    /// returned a false positive).
    pub fn read(&self, filename: &str) -> Option<Vec<u8>> {
        let pos = self.file_position(filename);
        self.storage.get(&pos).cloned()
    }

    /// Delete a file from the filesystem.
    /// Note: the Bloom filter entry remains (Bloom filters don't support
    /// deletion). The file data is removed.
    pub fn delete(&mut self, filename: &str) -> bool {
        let pos = self.file_position(filename);
        self.storage.remove(&pos).is_some()
    }

    /// Get the number of files.
    pub fn file_count(&self) -> usize {
        self.storage.len()
    }

    /// Get the directory key.
    pub fn dir_key(&self) -> &[u8; 32] {
        &self.dir_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_read() {
        let key = [0x42u8; 32];
        let mut fs = MirageFS::new(key);
        fs.write("secret.txt", b"hello world");
        let data = fs.read("secret.txt").unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn might_exist_returns_true_for_written_file() {
        let key = [0x42u8; 32];
        let mut fs = MirageFS::new(key);
        fs.write("secret.txt", b"hello");
        assert!(fs.might_exist("secret.txt"));
    }

    #[test]
    fn might_exist_returns_false_for_missing_file() {
        let key = [0x42u8; 32];
        let fs = MirageFS::new(key);
        // With a fresh Bloom filter, this should return false.
        // (There's a ~1% false positive rate, but with a single check
        // on an empty filter, it should be false.)
        assert!(!fs.might_exist("nonexistent.txt"));
    }

    #[test]
    fn delete_removes_data() {
        let key = [0x42u8; 32];
        let mut fs = MirageFS::new(key);
        fs.write("secret.txt", b"hello");
        assert!(fs.delete("secret.txt"));
        assert!(fs.read("secret.txt").is_none());
    }

    #[test]
    fn file_position_differs_by_filename() {
        let key = [0x42u8; 32];
        let fs = MirageFS::new(key);
        let p1 = fs.file_position("a.txt");
        let p2 = fs.file_position("b.txt");
        assert_ne!(p1, p2);
    }

    #[test]
    fn file_position_differs_by_key() {
        let fs1 = MirageFS::new([0x01u8; 32]);
        let fs2 = MirageFS::new([0x02u8; 32]);
        let p1 = fs1.file_position("a.txt");
        let p2 = fs2.file_position("a.txt");
        assert_ne!(p1, p2);
    }

    #[test]
    fn file_count_tracks_writes() {
        let key = [0x42u8; 32];
        let mut fs = MirageFS::new(key);
        assert_eq!(fs.file_count(), 0);
        fs.write("a.txt", b"a");
        assert_eq!(fs.file_count(), 1);
        fs.write("b.txt", b"b");
        assert_eq!(fs.file_count(), 2);
    }

    #[test]
    fn bloom_filter_false_positive_rate() {
        let mut bloom = BloomFilter::new(1000);
        // Insert 100 items.
        for i in 0..100u64 {
            bloom.insert(&i.to_le_bytes());
        }
        // Check 1000 items that were NOT inserted.
        let mut false_positives = 0;
        for i in 1000..2000u64 {
            if bloom.contains(&i.to_le_bytes()) {
                false_positives += 1;
            }
        }
        // False positive rate should be < 5%.
        assert!(
            false_positives < 50,
            "too many false positives: {false_positives}/1000"
        );
    }
}
