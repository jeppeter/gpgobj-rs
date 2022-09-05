
use super::gpgimpl::{GpgOp};
#[allow(unused_imports)]
use super::logger::{gpgobj_debug_out,gpgobj_log_get_timestamp};
use super::{gpgobj_log_trace,gpgobj_error_class,gpgobj_new_error};
use super::consts::{PUBKEY_ALGO_RSA,GPG_HEADER_EXTENSION_FLAG,GPG_EXTENSION_MASK,GPG_NORMAL_MASK,GPG_NORMAL_SHIFT,GPG_EXTHDR_MAX_CODE,GPG_EXTHDR_LEN_MASK,PKT_PUBLIC_KEY};
use num_bigint::{BigUint};
use std::error::Error;
use std::io::Write;


gpgobj_error_class!{GpgBaseError}


fn decode_gpg_header(code :&[u8]) -> Result<(u8,usize,usize),Box<dyn Error>> {
	let flag :u8;
	let hdrlen :usize;
	let mut tlen :usize;

	if code.len() < 1 {
		gpgobj_new_error!{GpgBaseError,"len [{}] < 1", code.len()}
	}

	if (code[0] & GPG_HEADER_EXTENSION_FLAG) != 0 {
		flag = code[0] & GPG_EXTENSION_MASK;
		if code.len() < 2 {
			gpgobj_new_error!{GpgBaseError,"len [{}] < 2" ,code.len()}
		}
		if code[1] == GPG_EXTHDR_MAX_CODE {
			hdrlen = 1 + 4 + 1;
			if code.len() < 6 {
				gpgobj_new_error!{GpgBaseError,"len [{}] < 6" ,code.len()}
			}
			tlen  = 0;
			tlen += (code[2] as usize) << 24;
			tlen += (code[3] as usize) << 16;
			tlen += (code[4] as usize) << 8;
			tlen += (code[5] as usize) << 0;
		} else if (code[1] & GPG_EXTHDR_LEN_MASK) != 0 {
			hdrlen = 1 + 2;
			if code.len() < 4 {
				gpgobj_new_error!{GpgBaseError,"len [{}] < 4" ,code.len()}
			}
			tlen = GPG_EXTHDR_LEN_MASK as usize;
			tlen += ((code[1] - GPG_EXTHDR_LEN_MASK) as usize ) << 8;
			tlen += code[2] as usize;
		} else {
			hdrlen = 1 + 1;
			if code.len() < 3 {
				gpgobj_new_error!{GpgBaseError,"len [{}] < 3" ,code.len()}		
			}
			tlen = code[2] as usize;
		}
	} else {
		flag = (code[0] >> GPG_NORMAL_SHIFT) & GPG_NORMAL_MASK;
		match code[0] & 0x3  {
			0 => {
				if code.len() < 2 {
					gpgobj_new_error!{GpgBaseError,"normal len [{}] < 2" ,code.len()}
				}
				hdrlen = 2;
				tlen = code[1] as usize;
			},
			1 => {
				if code.len() < 3 {
					gpgobj_new_error!{GpgBaseError,"normal len [{}] < 3" ,code.len()}
				}
				hdrlen = 3;
				tlen = (code[1] as usize) << 8;
				tlen |= code[2] as usize;
			},
			_ => {
				if code.len() < 5 {
					gpgobj_new_error!{GpgBaseError,"normal len [{}] < 3" ,code.len()}
				}
				hdrlen = 5;
				tlen = (code[1] as usize) << 24;
				tlen |= (code[2] as usize) << 16;
				tlen |= (code[3] as usize) << 8;
				tlen |= (code[4] as usize) << 0;
			},
		}
	}

	if code.len() < (tlen + hdrlen) {
		gpgobj_new_error!{GpgBaseError,"code [{}] < len[{}]", code.len(), tlen + hdrlen}
	}

	gpgobj_log_trace!("flag [0x{:02x}] hdrlen [0x{:x}] tlen [0x{:x}]", flag,hdrlen,tlen);
	Ok((flag,hdrlen,tlen))
}

pub struct GpgPubKey {
	pub version : u8,
	timestamp : u32,
	pub algo :u8,
	pub nums :Vec<BigUint>,
}

impl GpgOp for GpgPubKey {
	fn init_gpg() -> Self {
		GpgPubKey {
			version : 1,
			timestamp : 0,
			algo : PUBKEY_ALGO_RSA,
			nums : Vec::new(),
		}
	}

	fn decode_gpg(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let  retv :usize;
		let (flag , hdrlen,tlen) = decode_gpg_header(code)?;
		if flag != PKT_PUBLIC_KEY {
			gpgobj_new_error!{GpgBaseError,"flag [0x{:02x}] != [0x{:02x}]", flag,PKT_PUBLIC_KEY}
		}

		retv = hdrlen + tlen;
		Ok(retv)
	}

	fn encode_gpg(&self) -> Result<Vec<u8>, Box<dyn Error>> {
		let retv :Vec<u8> = Vec::new();
		Ok(retv)
	}

	fn print_gpg<U :Write>(&self,_name :&str,_tab :i32, _iowriter :&mut U) -> Result<(),Box<dyn Error>>{
		Ok(())
	}



}