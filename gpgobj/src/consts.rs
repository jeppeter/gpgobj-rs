
pub const GPG_HEADER_EXTENSION_FLAG :u8 = 0x40;
pub const GPG_EXTENSION_MASK :u8 = 0x3f;
pub const GPG_NORMAL_MASK :u8 = 0x1f;
pub const GPG_NORMAL_SHIFT :usize = 0x2;


pub const GPG_EXTHDR_LEN_MASK : u8 = 0xc0;
pub const GPG_EXTHDR_MAX_CODE : u8 = 0xff;

pub const PUBKEY_ALGO_RSA : u8 = 1;
pub const PUBKEY_ALGO_RSA_E : u8 = 2;
pub const PUBKEY_ALGO_RSA_S : u8 = 3;
pub const PUBKEY_ALGO_ELGAMAL_E :u8 = 16;
pub const PUBKEY_ALGO_DSA : u8 = 17;
pub const PUBKEY_ALGO_ECDH :u8       = 18;
pub const PUBKEY_ALGO_ECDSA :u8 = 19;
pub const PUBKEY_ALGO_ELGAMAL :u8 = 20;
pub const PUBKEY_ALGO_EDDSA :u8 = 22;
pub const PUBKEY_ALGO_PRIVATE10:u8 = 110;

pub const PKT_NONE :u8 = 0;
pub const PKT_PUBKEY_ENC :u8 = 1;
pub const PKT_SIGNATURE :u8 = 2;
pub const PKT_SYMKEY_ENC :u8 = 3;
pub const PKT_ONEPASS_SIG :u8 = 4;
pub const PKT_SECRET_KEY :u8 = 5;
pub const PKT_PUBLIC_KEY :u8 = 6;
pub const PKT_SECRET_SUBKEY :u8 = 7;
pub const PKT_COMPRESSED :u8 = 8;
pub const PKT_ENCRYPTED :u8 = 9;
pub const PKT_MARKER :u8 = 10;
pub const PKT_PLAINTEXT :u8 = 11;
pub const PKT_RING_TRUST :u8 = 12;
pub const PKT_USER_ID :u8 = 13;
pub const PKT_PUBLIC_SUBKEY :u8 = 14;
pub const PKT_OLD_COMMENT :u8 = 16;
pub const PKT_ATTRIBUTE :u8 = 17;
pub const PKT_ENCRYPTED_MDC :u8 = 18;
pub const PKT_MDC :u8 = 19;
pub const PKT_ENCRYPTED_AEAD :u8 = 20;
pub const PKT_COMMENT :u8 = 61;
pub const PKT_GPG_CONTROL :u8 = 63;

pub const DIGEST_ALGO_MD5 :u8 = 1;
pub const DIGEST_ALGO_SHA1 :u8 = 2;
pub const DIGEST_ALGO_RMD160 :u8 = 3;
pub const DIGEST_ALGO_SHA256 :u8 = 8;
pub const DIGEST_ALGO_SHA384 :u8 = 9;
pub const DIGEST_ALGO_SHA512 :u8 = 10;
pub const DIGEST_ALGO_SHA224 :u8 = 11;
pub const DIGEST_ALGO_PRIVATE10 :u8 = 110;

pub const CIPHER_ALGO_NONE :u8 = 0;
pub const CIPHER_ALGO_IDEA :u8 = 1;
pub const CIPHER_ALGO_3DES :u8 = 2;
pub const CIPHER_ALGO_CAST5 :u8 = 3;
pub const CIPHER_ALGO_BLOWFISH :u8 = 4;
pub const CIPHER_ALGO_AES :u8 = 7;
pub const CIPHER_ALGO_AES192 :u8 = 8;
pub const CIPHER_ALGO_AES256 :u8 = 9;
pub const CIPHER_ALGO_TWOFISH :u8 = 10;
pub const CIPHER_ALGO_CAMELLIA128 :u8 = 11;
pub const CIPHER_ALGO_CAMELLIA192 :u8 = 12;
pub const CIPHER_ALGO_CAMELLIA256 :u8 = 13;
pub const CIPHER_ALGO_PRIVATE10 :u8 = 110;


pub (crate) const GPG_CRC24_INIT :u32 = 0xB704CE;
pub (crate) const GPG_CRC24_POLY :u32 = 0x864CFB;
