
//use super::{gpgobj_error_class,gpgobj_new_error};
use super::consts::{GPG_CRC24_INIT,GPG_CRC24_POLY};
use lazy_static::lazy_static;


lazy_static !{
	static ref GPG_CRC24_TABLE :Vec<u32> = {
		let mut retv :Vec<u32> = Vec::new();
		let mut i :usize;
		for _ in 0..256 {
			retv.push(0);
		}
		i = 0;
		for j in 0..128 {
			let mut t :u32 ;
			t = retv[j];
			if (t & 0x00800000) != 0 {
				t <<= 1;
				retv[i] = t ^ GPG_CRC24_POLY;
				i += 1;
				retv[i] = t;
				i += 1;
			} else {
				t <<= 1;
				retv[i] = t;
				i += 1;
				retv[i] = t ^ GPG_CRC24_POLY;
				i += 1;
			}
		}

		retv
	};
}

pub struct GpgCrc24 {
	crc : u32,	
}


impl GpgCrc24 {
	pub fn new() -> GpgCrc24 {
		GpgCrc24 {
			crc : GPG_CRC24_INIT,
		}
	}

	pub fn get(&self) -> u32 {
		return self.crc;
	}

	pub fn update(&mut self, buf :&[u8]) {
		let mut crc :u32 = self.crc;
		for i in 0..buf.len() {
			let cb :u8 = ((crc >> 16) & 0xff) as u8;
			let cidx : usize = (cb ^ (buf[i])) as usize;
			crc = (crc << 8) ^ GPG_CRC24_TABLE[cidx];
		}
		self.crc = crc & 0x00ffffff;
	}
}
