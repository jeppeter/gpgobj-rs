
use super::gpgimpl::{GpgOp};
use std::error::Error;
use super::{gpgobj_log_trace,gpgobj_error_class,gpgobj_new_error};
use super::strop::{gpgobj_format_line};
use super::logger::{gpgobj_debug_out,gpgobj_log_get_timestamp};
use chrono::prelude::*;
use std::io::Write;

gpgobj_error_class!{GpgBaseError}


pub struct GpgTime {
	timeval :u32,
}


impl GpgTime {
	fn time_to_str(&self) -> String {
		let n : NaiveDateTime=  NaiveDateTime::from_timestamp(self.timeval as i64, 0);	
		let dt :DateTime<Utc> = DateTime::from_utc(n,Utc);
		return format!("{}",dt.format("%Y-%m-%d %H:%M:%S"));
	}
}

impl GpgOp for GpgTime {
	fn init_gpg() -> Self {
		GpgTime {
			timeval : 0,
		}
	}

	fn decode_gpg(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let retv :usize = 4;

		if code.len() < retv {
			gpgobj_new_error!{GpgBaseError,"[{}] < {}", code.len(),retv}
		}		
		self.timeval = 0;
		self.timeval |= (code[0] as u32) << 24;
		self.timeval |= (code[1] as u32) << 16;
		self.timeval |= (code[2] as u32) << 8;
		self.timeval |= (code[3] as u32) << 0;
		gpgobj_log_trace!("timeval {}", self.timeval);
		Ok(retv)
	}

	fn encode_gpg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		retv.push(((self.timeval >> 24) & 0xff) as u8);
		retv.push(((self.timeval >> 16) & 0xff) as u8);
		retv.push(((self.timeval >> 8) & 0xff) as u8);
		retv.push(((self.timeval >> 0) & 0xff) as u8);
		Ok(retv)
	}

	fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		let c = gpgobj_format_line(tab,&format!("{} time {}",name,self.time_to_str()));
		iowriter.write(c.as_bytes())?;
		Ok(())
	}
}