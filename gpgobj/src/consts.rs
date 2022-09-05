
pub const GPG_HEADER_EXTENSION_FLAG :u8 = 0x40;
pub const GPG_EXTENSION_MASK :u8 = 0x3f;
pub const GPG_NORMAL_MASK :u8 = 0x1f;
pub const GPG_NORMAL_SHIFT :usize = 0x2;


pub const GPG_EXTHDR_LEN_MASK : u8 = 0xc0;
pub const GPG_EXTHDR_MAX_CODE : u8 = 0xff;

pub const PUBKEY_ALGO_RSA : u8 = 1;

pub const PKT_PUBLIC_KEY :u8 = 6;
