
use super::gpgimpl::{GpgOp};
#[allow(unused_imports)]
use super::logger::{gpgobj_debug_out,gpgobj_log_get_timestamp};
#[allow(unused_imports)]
use super::{gpgobj_log_trace,gpgobj_error_class,gpgobj_new_error,gpgobj_debug_buffer_trace,gpgobj_format_buffer_log};
use super::strop::{gpgobj_format_line};
#[allow(unused_imports)]
use super::base::{GpgTime,GpgVersion,decode_gpgobj_header,encode_gpgobj_header,GpgBigNum,GpgEncAlgorithm};
use super::consts::{PKT_PUBLIC_KEY};
use std::error::Error;
use std::io::Write;
use gpgobj_codegen::{gpgobj_sequence};


gpgobj_error_class!{GpgComplexError}

#[derive(Clone)]
pub struct GpgVec<T : GpgOp + Clone> {
	pub val : Vec<T>,
}

impl<T: GpgOp + Clone> GpgOp for GpgVec<T> {
	fn decode_gpg(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut v :T = T::init_gpg(); 
		let mut retv :usize = 0;
		self.val = Vec::new();

		while retv < code.len() {
			let ores = v.decode_gpg(&code[retv..]);
			if ores.is_err() {
				let e = ores.err().unwrap();
				if code.len() > 20 {
					gpgobj_debug_buffer_trace!(code.as_ptr(),20,"GpgVec decode [{}:0x{:x}] error[{:?}]", code.len(),code.len(),e);
				} else {
					gpgobj_debug_buffer_trace!(code.as_ptr(),code.len(),"GpgVec decode [{}:0x{:x}] error[{:?}]", code.len(),code.len(),e);
				}
				/*we make end of the line*/
				break;
			} 
			self.val.push(v.clone());
			retv += ores.unwrap();			
		}
		Ok(retv)
	}

	fn encode_gpg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		let mut cvec :Vec<u8>;
		for i in 0..self.val.len() {
			cvec = self.val[i].encode_gpg()?;
			retv.extend(cvec.iter().copied());
		}
		Ok(retv)
	}

	fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		if self.val.len() == 0 {
			iowriter.write(gpgobj_format_line(tab,&format!("{}:<Absent>", name)).as_bytes())?;
		} else {
			let mut c :String;
			c = gpgobj_format_line(tab,&format!("{} GpgVec [{}]", name,self.val.len()));
			iowriter.write(c.as_bytes())?;
			for i in 0..self.val.len() {
				c = format!("{}[{}]",name,i);
				self.val[i].print_gpg(&c,tab+1,iowriter )?;
			}
		}
		Ok(())
	}

	fn init_gpg() -> Self {
		GpgVec {
			val : Vec::new(),
		}
	}
}

#[gpgobj_sequence(matchid=PKT_PUBLIC_KEY,extflagname=extflag,matchidname=matchid)]
pub struct GpgPubKey {
	pub extflag : bool,
	pub matchid : u8,
	pub version : GpgVersion,
	pub timestamp : GpgTime,
	pub algo :GpgEncAlgorithm,
	pub nums :GpgVec<GpgBigNum>,
}




/*
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
		let (flag , hdrlen,tlen) = decode_gpgobj_header(code)?;
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
*/