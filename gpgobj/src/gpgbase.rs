
use super::gpgimpl::{GpgOp};
use super::logger::{gpgobj_debug_out,gpgobj_log_get_timestamp};
use super::{gpgobj_log_trace};

pub struct GpgPubKey {
	pub version : u8,
	pub timestamp : u32,
	pub algo :u8,
}