use std::fmt::Display;
use std::{collections::HashSet, fs::File};
use std::convert::TryInto;
use std::hash::Hash;
use anyhow::{Result,anyhow};
use md5::{Md5, Digest};
use memmap::MmapOptions;
use sha1::Sha1;
use sha2::Sha256;
use walkdir::DirEntry;

use crate::filescanner::FileScanner;
use crate::scanner_result::ScannerFinding;

const MD5_SIZE: usize = 128 / 8;
const SHA1_SIZE: usize = 160 / 8;
const SHA256_SIZE: usize = 256 / 8;

#[derive(Eq, Clone)]
pub enum CryptoHash {
    MD5([u8; MD5_SIZE]),
    SHA1([u8; SHA1_SIZE]),
    SHA256([u8; SHA256_SIZE])
}

impl PartialEq for CryptoHash {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::MD5(l0), Self::MD5(r0)) => l0 == r0,
            (Self::SHA1(l0), Self::SHA1(r0)) => l0 == r0,
            (Self::SHA256(l0), Self::SHA256(r0)) => l0 == r0,
            (_, _) => false
        }
    }
}

impl Hash for CryptoHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            CryptoHash::MD5(h) => h.hash(state),
            CryptoHash::SHA1(h) => h.hash(state),
            CryptoHash::SHA256(h) => h.hash(state),
        }
    }
}

impl Display for CryptoHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoHash::MD5(h) => write!(f, "MD5:{}", hex::encode(h)),
            CryptoHash::SHA1(h) => write!(f, "SHA1:{}", hex::encode(h)),
            CryptoHash::SHA256(h) => write!(f, "SHA256:{}", hex::encode(h)),
        }
    }
}

#[derive(Default)]
pub struct HashScanner {
    hashes: HashSet<CryptoHash>,

    has_md5_hashes: bool,
    has_sha1_hashes: bool,
    has_sha256_hashes: bool,
}

impl HashScanner {
    pub fn with_hashes(mut self, hashes: &Vec<String>) -> Result<Self> {
        for hash in hashes.iter() {
            let crypto_hash = Self::parse_hash(hash)?;
            match &crypto_hash {
                CryptoHash::MD5(_) => self.has_md5_hashes = true,
                CryptoHash::SHA1(_) => self.has_sha1_hashes = true,
                CryptoHash::SHA256(_) => self.has_sha256_hashes = true,
            }
            self.hashes.insert(Self::parse_hash(hash)?);
        }
        Ok(self)
    }

    fn parse_hash(hash: &str) -> Result<CryptoHash> {
        let bytes = hex::decode(hash)?;
        match bytes.len() {
            MD5_SIZE => Ok(CryptoHash::MD5(bytes.try_into().unwrap())),
            SHA1_SIZE => Ok(CryptoHash::SHA1(bytes.try_into().unwrap())),
            SHA256_SIZE => Ok(CryptoHash::SHA256(bytes.try_into().unwrap())),
            _ => Err(anyhow!("invalid hash length of '{}'", hash)),
        }
    }

    fn scan_slice<S: AsRef<[u8]>>(&self, slice: S) -> Vec<anyhow::Result<ScannerFinding>> {
        let mut hashes = Vec::new();

        if self.has_md5_hashes {
            let mut hasher = Md5::new();
            hasher.update(&slice);
            let result = hasher.finalize();
            let crypto_hash = CryptoHash::MD5(result.try_into().unwrap());
            hashes.push(crypto_hash);
        }

        if self.has_sha1_hashes {
            let mut hasher = Sha1::new();
            hasher.update(&slice);
            let result = hasher.finalize();
            let crypto_hash = CryptoHash::SHA1(result.try_into().unwrap());
            hashes.push(crypto_hash);
        }

        if self.has_sha256_hashes {
            let mut hasher = Sha256::new();
            hasher.update(&slice);
            let result = hasher.finalize();
            let crypto_hash = CryptoHash::SHA256(result.try_into().unwrap());
            hashes.push(crypto_hash);
        }

        let mut results = Vec::new();
        for h in &hashes {
            if self.hashes.contains(&h) {
                results.push(Ok(ScannerFinding::Hash(h.clone())));
            }
        }
        results
    }
}

impl FileScanner for HashScanner {
    fn scan_file(&self, entry: &DirEntry) -> Vec<anyhow::Result<ScannerFinding>> {
        const EMPTY_SLICE: [u8; 0] = [];

        match entry.metadata() {
            Err(why) => {
                return vec![Err(anyhow!("unable to obtain metadata for file '{}'", why))]
            }
            Ok(metadata) => {
                if metadata.len() == 0 {
                    self.scan_slice(&EMPTY_SLICE)
                } else {
                    let file = File::open(entry.path()).unwrap();
                    let mmap = unsafe { MmapOptions::new().map(&file).unwrap() };
                    self.scan_slice(&mmap)
                }
            }
        }

    }
}