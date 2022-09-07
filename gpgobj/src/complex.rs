
use super::gpgimpl::{GpgOp};
#[allow(unused_imports)]
use super::logger::{gpgobj_debug_out,gpgobj_log_get_timestamp};
#[allow(unused_imports)]
use super::{gpgobj_log_trace,gpgobj_error_class,gpgobj_new_error,gpgobj_debug_buffer_trace,gpgobj_format_buffer_log};
use super::strop::{gpgobj_format_line};
#[allow(unused_imports)]
use super::base::{GpgTime,GpgVersion,decode_gpgobj_header,encode_gpgobj_header,GpgBigNum,GpgEncAlgorithm,GpgData};
use super::consts::{PKT_PUBLIC_KEY,PKT_USER_ID};
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

#[gpgobj_sequence(matchid=PKT_USER_ID,extflagname=extflag,matchidname=matchid)]
pub struct GpgUserId {
	pub extflag : bool,
	pub matchid : u8,
	pub data : GpgData,
}

#[gpgobj_sequence()]
pub struct GpgPubFileEnc {
	pub pubkey : GpgPubKey,
	pub userid : GpgUserId,
}