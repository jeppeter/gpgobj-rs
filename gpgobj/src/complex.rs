
use super::gpgimpl::{GpgOp};
#[allow(unused_imports)]
use super::logger::{gpgobj_debug_out,gpgobj_log_get_timestamp};
use super::{gpgobj_log_trace,gpgobj_error_class,gpgobj_new_error};
use super::strop::{gpgobj_format_line};
use super::base::{GpgTime,GpgVersion,decode_gpg_header,GpgBigNum,GpgEncAlgorithm};
use super::consts::{PKT_PUBLIC_KEY};
use std::error::Error;
use std::io::Write;


gpgobj_error_class!{GpgComplexError}

pub struct GpgPubKey {
	pub version : GpgVersion,
	pub timestamp : GpgTime,
	pub algo :GpgEncAlgorithm,
	pub nums :Vec<GpgBigNum>,
}


impl GpgOp for GpgPubKey {
	fn init_gpg() -> Self {
		GpgPubKey {
			version : GpgVersion::init_gpg(),
			timestamp : GpgTime::init_gpg(),
			algo : GpgEncAlgorithm::init_gpg(),
			nums : Vec::new(),
		}
	}

	fn decode_gpg(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let  retv :usize;
		let (flag , hdrlen,tlen) = decode_gpg_header(code)?;
		let mut curidx : usize = 0;
		if flag != PKT_PUBLIC_KEY {
			gpgobj_new_error!{GpgComplexError,"flag [0x{:02x}] != [0x{:02x}]", flag,PKT_PUBLIC_KEY}
		}

		if code.len() < (hdrlen + tlen) {
			gpgobj_new_error!{GpgComplexError,"code [{}] < {} + {}", code.len(),hdrlen, tlen}
		}

		if tlen < (1 + 4 + 1) {
			gpgobj_new_error!{GpgComplexError,"tlen [{}] < 1 + 4 + 1", tlen}	
		}

		curidx += self.version.decode_gpg(&code[hdrlen+curidx..hdrlen+tlen])?;
		curidx += self.timestamp.decode_gpg(&code[hdrlen+curidx..hdrlen+tlen])?;
		curidx += self.algo.decode_gpg(&code[hdrlen+curidx..hdrlen+tlen])?;
		self.nums = Vec::new();
		while curidx < tlen {
			let mut bn  = GpgBigNum::init_gpg();
			curidx += bn.decode_gpg(&code[hdrlen+curidx..hdrlen+tlen])?;
			self.nums.push(bn.clone());
		}

		retv = hdrlen + tlen;
		gpgobj_log_trace!("decode GpgPubKey [0x{:x}]",retv);
		Ok(retv)
	}

	fn encode_gpg(&self) -> Result<Vec<u8>, Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		let mut cvec :Vec<u8>;
		cvec = self.version.encode_gpg()?;
		retv.extend(cvec.iter().copied());
		cvec = self.timestamp.encode_gpg()?;
		retv.extend(cvec.iter().copied());
		cvec = self.algo.encode_gpg()?;
		retv.extend(cvec.iter().copied());
		for i in 0..self.nums.len() {
			cvec = self.nums[i].encode_gpg()?;
			retv.extend(cvec.iter().copied());
		}
		Ok(retv)
	}

	fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>>{
		let mut c :String;
		c = gpgobj_format_line(tab,&format!("{} Public Key", name));
		iowriter.write(c.as_bytes())?;
		self.version.print_gpg("version",tab + 1, iowriter)?;
		self.timestamp.print_gpg("timestamp",tab + 1, iowriter)?;
		self.algo.print_gpg("algo",tab + 1, iowriter)?;
		for i in 0..self.nums.len() {
			c = format!("num[{}]",i);
			self.nums[i].print_gpg(&c,tab + 1, iowriter)?;
		}
		Ok(())
	}
}