
use super::gpgimpl::{GpgOp};
use super::logger::{gpgobj_debug_out,gpgobj_log_get_timestamp};
use super::{gpgobj_log_trace};
use super::consts::{PUBKEY_ALGO_RSA};

pub struct GpgPubKey {
	pub version : u8,
	timestamp : u32,
	pub algo :u8,
	pub nums :Vec<BigUint>,
}

impl GpgOp for GpgPubKey {
	pub fn init_gpg() -> Self {
		GpgPubKey {
			version : 1,
			timestamp : 0,
			algo : PUBKEY_ALGO_RSA,
			nums : Vec::new(),
		}
	}

	pub decode_gpg(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		
	}
}