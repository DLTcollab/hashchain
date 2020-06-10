use self::HashChain::{BLAKE3, SHA1, SHA224, SHA256, SHA384, SHA512};
use std::process::exit;

/// Macro used to convert array reference to fixed-size array
macro_rules! fixed_size {
    ($len:literal, $data:ident) => {{
        let mut arr = [0; $len];
        let bytes = &$data[..$len];
        arr.copy_from_slice(bytes);
        arr
    }};
}

pub enum HashChain {
    SHA1([u8; 20]),
    SHA224([u8; 28]),
    SHA256([u8; 32]),
    SHA384([u8; 48]),
    SHA512([u8; 64]),
    BLAKE3([u8; 32]),
}

impl HashChain {
    /// Test if two HashChain is equal, takes advantage of safe memcmp from openssl
    pub fn equal(a: &HashChain, b: &HashChain) -> bool {
        let ca = HashChain::convert(a);
        let cb = HashChain::convert(b);
        openssl::memcmp::eq(ca, cb)
    }

    /// Convert type [u8] to type HashChain
    pub fn convert<'a>(data: &'a HashChain) -> &'a [u8] {
        match data {
            SHA1(data) => data,
            SHA224(data) => data,
            SHA256(data) => data,
            SHA384(data) => data,
            SHA512(data) => data,
            BLAKE3(data) => data,
        }
    }

    /// Initialize HashChain with existing data
    /// This function **won't** hash the data.
    /// It will only encapsulate the given data to type HashChain.
    ///
    /// This function is used in hashchain_verify, where we already have hashed data
    ///
    /// # Arguments
    ///
    /// * `algo`: Hash algorithms
    /// * `data`: Hashed data
    pub fn init(algo: &str, data: &[u8]) -> HashChain {
        match algo {
            "sha1" => SHA1(fixed_size!(20, data)),
            "sha224" => SHA224(fixed_size!(28, data)),
            "sha256" => SHA256(fixed_size!(32, data)),
            "sha384" => SHA384(fixed_size!(48, data)),
            "sha512" => SHA512(fixed_size!(64, data)),
            "blake3" => BLAKE3(fixed_size!(32, data)),
            _ => {
                println!("Unsupported hash type");
                exit(1);
            }
        }
    }

    /// Initialize HashChain with given seed.
    /// This function will hash the seed, then store into HashChain.
    ///
    /// # Arguments
    ///
    /// * `algo`: Hash algorithms
    /// * `seed`: The seed for initialization
    pub fn init_seed(algo: &str, seed: &[u8]) -> HashChain {
        match algo {
            "sha1" => SHA1(openssl::sha::sha1(&seed)),
            "sha224" => SHA224(openssl::sha::sha224(&seed)),
            "sha256" => SHA256(openssl::sha::sha256(&seed)),
            "sha384" => SHA384(openssl::sha::sha384(&seed)),
            "sha512" => SHA512(openssl::sha::sha512(&seed)),
            "blake3" => BLAKE3(*blake3::hash(&seed).as_bytes()),
            _ => {
                println!("Unsupported hash type");
                exit(1);
            }
        }
    }

    /// Encapsulated hash function.
    ///
    /// Supported hash algorithms
    /// * SHA1
    /// * SHA224
    /// * SHA256
    /// * SHA384
    /// * SHA512
    /// * BLAKE3
    ///
    /// # Arguments
    ///
    /// * `data`: Data with type HashChain
    pub fn hash(data: HashChain) -> HashChain {
        match data {
            SHA1(data) => SHA1(openssl::sha::sha1(&data)),
            SHA224(data) => SHA224(openssl::sha::sha224(&data)),
            SHA256(data) => SHA256(openssl::sha::sha256(&data)),
            SHA384(data) => SHA384(openssl::sha::sha384(&data)),
            SHA512(data) => SHA512(openssl::sha::sha512(&data)),
            BLAKE3(data) => BLAKE3(*blake3::hash(&data).as_bytes()),
        }
    }
}
