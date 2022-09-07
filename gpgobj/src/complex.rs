
use super::gpgimpl::{GpgOp};
#[allow(unused_imports)]
use super::logger::{gpgobj_debug_out,gpgobj_log_get_timestamp};
#[allow(unused_imports)]
use super::{gpgobj_log_trace,gpgobj_error_class,gpgobj_new_error,gpgobj_debug_buffer_trace,gpgobj_format_buffer_log};
use super::strop::{gpgobj_format_line};
#[allow(unused_imports)]
use super::base::{GpgTime,GpgVersion,decode_gpgobj_header,encode_gpgobj_header,GpgBigNum,GpgEncAlgorithm,GpgData,GpgU32,GpgU16,get_pubk_str,get_digalgo_str,get_pubk_nsig_cnt,GpgU8,cipher_algo_str};
use super::consts::*;
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

pub struct GpgSignature {
	pub matchid :u8,
	pub extflag : bool,
	pub version :u8,
	pub constv :u8,
	pub sigcls :u8,
	pub timestamp :GpgTime,
	pub keyid :Vec<GpgU32>,
	pub pubkalgo : u8,
	pub digalgo : u8,
	pub hashed :GpgData,
	pub unhashed :GpgData,
	pub digstart : Vec<u8>,
	pub data :Vec<GpgBigNum>,

}


impl GpgOp for GpgSignature {
	fn init_gpg() -> Self {
		GpgSignature {
			matchid : PKT_SIGNATURE,
			extflag : false,
			version : 3,
			constv  : 5,
			sigcls : 0,
			timestamp  :GpgTime::init_gpg(),
			keyid : Vec::new(),
			pubkalgo : 0,
			digalgo : 0,
			hashed : GpgData::init_gpg(),
			unhashed : GpgData::init_gpg(),
			digstart : Vec::new(),
			data : Vec::new(),
		}
	}

	fn decode_gpg(&mut self, code :&[u8]) -> Result<usize, Box<dyn Error>> {
		let mut retv :usize = 0;
		let endsize :usize;
		let (_flag,_extflag,_hdrlen,_tlen) = decode_gpgobj_header(code)?;
		if _flag != PKT_SIGNATURE {
			gpgobj_new_error!{GpgComplexError,"flag [0x{:x}] != PKT_SIGNATURE [0x{:x}]", _flag,PKT_SIGNATURE}
		}

		self.matchid = _flag;
		self.extflag = _extflag;
		retv += _hdrlen;
		endsize = _hdrlen + _tlen;

		if endsize < (retv + 1) {
			gpgobj_new_error!{GpgComplexError,"no version space [{}] endsize [{}]", retv, endsize}
		}
		self.version = code[retv];
		retv += 1;
		if self.version < 4 {
			if endsize < (retv + 1) {
				gpgobj_new_error!{GpgComplexError,"no constv space [{}] endsize [{}]", retv, endsize}
			}
			self.constv = code[retv];
			retv += 1;
		}
		if endsize < (retv + 1) {
			gpgobj_new_error!{GpgComplexError,"no sig_class space [{}] endsize [{}]", retv, endsize}
		}
		self.sigcls = code[retv];
		retv += 1;

		if self.version < 4 {
			if endsize < (retv + 4 + 4 + 4) {
				gpgobj_new_error!{GpgComplexError,"no timestamp keyid space [{}] endsize [{}]", retv, endsize}
			}
			retv += self.timestamp.decode_gpg(&(code[retv..]))?;
			self.keyid = Vec::new();
			for _ in 0..2{
				let mut t :GpgU32 = GpgU32::init_gpg();
				retv += t.decode_gpg(&code[retv..])?;
				self.keyid.push(t.clone());
			}
		}

		if endsize < (retv + 1) {
			gpgobj_new_error!{GpgComplexError,"no pubkalgo space [{}] endsize [{}]", retv, endsize}
		}
		self.pubkalgo = code[retv];
		retv += 1;

		if endsize < (retv + 1) {
			gpgobj_new_error!{GpgComplexError,"no digalgo space [{}] endsize [{}]", retv, endsize}
		}
		self.digalgo = code[retv];
		retv += 1;

		self.hashed = GpgData::init_gpg();
		self.unhashed = GpgData::init_gpg();

		if self.version >= 4 {
			let mut g16 :GpgU16 = GpgU16::init_gpg();
			retv += g16.decode_gpg(&code[retv..])?;
			if g16.data != 0 {
				let cend :usize = g16.data as usize + retv;
				if endsize < cend {
					gpgobj_new_error!{GpgComplexError,"no hashed  space [{}] + [{}] endsize [{}]", retv, g16.data, endsize}
				}
				retv += self.hashed.decode_gpg(&code[retv..cend])?;
			}

			retv += g16.decode_gpg(&code[retv..])?;
			if g16.data != 0 {
				let cend :usize = g16.data as usize + retv;
				if endsize < cend {
					gpgobj_new_error!{GpgComplexError,"no unhashed  space [{}] + [{}] endsize [{}]", retv, g16.data, endsize}
				}
				retv += self.unhashed.decode_gpg(&code[retv..cend])?;
			}
		}

		if endsize < (retv + 2) {
			gpgobj_new_error!{GpgComplexError,"no digstart  space [{}]  endsize [{}]", retv, endsize}
		}

		self.digstart = Vec::new();
		for _ in 0..2 {
			self.digstart.push(code[retv]);
			retv += 1;
		}

		let cnt = get_pubk_nsig_cnt(self.pubkalgo);
		self.data = Vec::new();
		if cnt == 0 {
			let mut vt :GpgBigNum = GpgBigNum::init_gpg();
			retv += vt.decode_gpg(&code[retv..])?;
			self.data.push(vt.clone());
		} else {
			for _ in 0..cnt {
				let mut vt :GpgBigNum = GpgBigNum::init_gpg();
				retv += vt.decode_gpg(&code[retv..])?;
				self.data.push(vt.clone());
			}
		}

		if retv != endsize {
			gpgobj_new_error!{GpgComplexError,"not complete Signature size [0x{:x}] != [0x{:x}]", retv,endsize}
		}
		Ok(retv)
	}

	fn encode_gpg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8>;
		let mut encv :Vec<u8> = Vec::new();
		let mut cv :Vec<u8>;

		encv.push(self.version);
		if self.version < 4 {
			encv.push(self.constv);
		}
		encv.push(self.sigcls);

		if self.version < 4 {
			cv = self.timestamp.encode_gpg()?;
			encv.extend(cv.iter().copied());

			if self.keyid.len() != 2 {
				gpgobj_new_error!{GpgComplexError,"keyid.len != 2"}
			}
			for i in 0..self.keyid.len() {
				cv = self.keyid[i].encode_gpg()?;
				encv.extend(cv.iter().copied());				
			}
		}

		encv.push(self.pubkalgo);
		encv.push(self.digalgo);

		if self.version >= 4 {
			let mut nn :GpgU16 = GpgU16::init_gpg();
			nn.data = self.hashed.data.len() as u16;
			cv = nn.encode_gpg()?;
			encv.extend(cv.iter().copied());
			if nn.data != 0 {
				cv = self.hashed.encode_gpg()?;
				encv.extend(cv.iter().copied());
			}

			nn.data = self.unhashed.data.len() as u16;
			cv = nn.encode_gpg()?;
			encv.extend(cv.iter().copied());
			if nn.data != 0 {
				cv = self.unhashed.encode_gpg()?;
				encv.extend(cv.iter().copied());
			}
		}

		if self.digstart.len() != 2 {
			gpgobj_new_error!{GpgComplexError,"digstart.len != 2"}
		}

		cv = self.digstart.clone();
		encv.extend(cv.iter().copied());
		let cnt = get_pubk_nsig_cnt(self.pubkalgo);
		if cnt == 0 {
			if self.data.len() < 1 {
				gpgobj_new_error!{GpgComplexError,"data len {} < cnt {} for 0x{:x}", self.data.len() ,cnt, self.pubkalgo}
			}
			cv = self.data[0].encode_gpg()?;
			encv.extend(cv.iter().copied());
		} else {
			if self.data.len() < cnt {
				gpgobj_new_error!{GpgComplexError,"data len {} < cnt {} for 0x{:x}", self.data.len() ,cnt, self.pubkalgo}
			}
			for i in 0..cnt {
				cv = self.data[i].encode_gpg()?;
				encv.extend(cv.iter().copied());
			}
		}
		retv = encode_gpgobj_header(self.matchid,self.extflag,encv.len())?;
		retv.extend(encv.iter().copied());
		Ok(retv)
	}

	fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		let mut s :String;
		s = gpgobj_format_line(tab , &format!("{} GpgSignature", name));
		iowriter.write(s.as_bytes())?;
		s = gpgobj_format_line(tab +1  , &format!("version {}", self.version));
		iowriter.write(s.as_bytes())?;
		s = gpgobj_format_line(tab +1  , &format!("sigcls {}", self.sigcls));
		iowriter.write(s.as_bytes())?;
		if self.version < 4 {

			self.timestamp.print_gpg("timestamp", tab + 1, iowriter)?;
			if self.keyid.len() < 2 {
				gpgobj_new_error!{GpgComplexError,"keyid.len {} < 2", self.keyid.len()}
			}
			for i in 0..self.keyid.len() {
				let c = format!("keyid[{}]",i);
				self.keyid[i].print_gpg(&c,tab+1,iowriter)?;
			}			
		} 
		s = gpgobj_format_line(tab + 1, &format!("pubkalgo {}", get_pubk_str(self.pubkalgo)));
		iowriter.write(s.as_bytes())?;

		s = gpgobj_format_line(tab + 1, &format!("digalgo {}", get_digalgo_str(self.digalgo)));
		iowriter.write(s.as_bytes())?;

		if self.version >= 4 {
			self.hashed.print_gpg("hashed", tab + 1, iowriter)?;
			self.unhashed.print_gpg("unhashed",tab + 1, iowriter)?;
		}

		if self.digstart.len() < 2 {
			gpgobj_new_error!{GpgComplexError,"digstart.len < 2"}
		}

		s = gpgobj_format_line(tab + 1 ,&format!("digstart [0x{:x}] [0x{:x}]",self.digstart[0],self.digstart[1]));
		iowriter.write(s.as_bytes())?;
		let cnt = get_pubk_nsig_cnt(self.pubkalgo);
		if self.data.len() < cnt {
			gpgobj_new_error!{GpgComplexError,"data.len {} < cnt {}",self.data.len(),cnt}
		}
		for i in 0..self.data.len() {
			let c = format!("data[{}]",i);
			self.data[i].print_gpg(&c,tab+1,iowriter)?;
		}
		Ok(())
	}
}

#[gpgobj_sequence()]
pub struct GpgPubKeyFile {
	pub pubkey : GpgPubKey,
	pub userid : GpgUserId,
	pub signature :GpgSignature,
}

pub struct GpgSessionKey {
	pub matchid :u8,
	pub extflag :bool,
	pub version :GpgVersion,
	pub cipheralgo :GpgU8,
	pub mode :GpgU8,
	pub hashalgo :GpgU8,
	pub salt :GpgData,
	pub cnt :GpgU8,
	pub seskey :GpgData,
}

impl GpgOp for GpgSessionKey {
	fn init_gpg() -> Self {
		let mut retv  = GpgSessionKey {
			matchid : PKT_SYMKEY_ENC,
			extflag : false,
			version : GpgVersion::init_gpg(),
			cipheralgo : GpgU8::init_gpg(),
			mode :GpgU8::init_gpg(),
			hashalgo :GpgU8::init_gpg(),
			salt : GpgData::init_gpg(),
			cnt :GpgU8::init_gpg(),
			seskey : GpgData::init_gpg(),
		};
		retv.version.version = 4;
		retv
	}

	fn decode_gpg(&mut self, code :&[u8]) -> Result<usize, Box<dyn Error>> {
		let mut retv :usize = 0;
		let endsize :usize;
		let (_flag,_extflag,_hdrlen,_tlen) = decode_gpgobj_header(code)?;
		if _flag != PKT_SYMKEY_ENC {
			gpgobj_new_error!{GpgComplexError,"flag [0x{:x}] != PKT_SYMKEY_ENC [0x{:x}]", _flag,PKT_SYMKEY_ENC}
		}

		self.matchid = _flag;
		self.extflag = _extflag;
		retv += _hdrlen;
		endsize = _hdrlen + _tlen;

		if endsize < (retv + 1) {
			gpgobj_new_error!{GpgComplexError,"no version space [{}] endsize [{}]", retv, endsize}
		}
		retv += self.version.decode_gpg(&code[retv..])?;
		if self.version.version != 4 {
			gpgobj_new_error!{GpgComplexError,"version {} != 4" ,self.version.version}
		}
		retv += self.cipheralgo.decode_gpg(&code[retv..])?;
		retv += self.mode.decode_gpg(&code[retv..])?;
		if (self.mode.data & 0x3 ) != self.mode.data {
			gpgobj_new_error!{GpgComplexError,"mode {} not in 0..3", self.mode.data}
		}
		retv += self.hashalgo.decode_gpg(&code[retv..])?;
		if self.mode.data == 1 || self.mode.data == 3 {
			retv += self.salt.decode_gpg(&code[retv..(retv+8)])?;			
		}

		if self.mode.data == 3 {
			retv += self.cnt.decode_gpg(&code[retv..])?;
		}

		self.seskey = GpgData::init_gpg();
		if endsize > retv {
			retv += self.seskey.decode_gpg(&code[retv..endsize])?;
		}
		Ok(retv)
	}

	fn encode_gpg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8>;
		let mut encv :Vec<u8> = Vec::new();
		let mut cv :Vec<u8>;

		if self.version.version != 4 {
			gpgobj_new_error!{GpgComplexError,"version {} != 4" ,self.version.version}
		}

		if self.matchid != PKT_SYMKEY_ENC {
			gpgobj_new_error!{GpgComplexError,"not PKT_SYMKEY_ENC {}" ,self.matchid}
		}

		if (self.mode.data & 0x3 ) != self.mode.data {
			gpgobj_new_error!{GpgComplexError,"mode {} not in 0..3", self.mode.data}
		}

		cv = self.version.encode_gpg()?;
		encv.extend(cv.iter().copied());

		cv = self.cipheralgo.encode_gpg()?;
		encv.extend(cv.iter().copied());

		cv = self.mode.encode_gpg()?;
		encv.extend(cv.iter().copied());

		cv = self.hashalgo.encode_gpg()?;
		encv.extend(cv.iter().copied());

		if self.mode.data == 1 || self.mode.data == 3 {
			if self.salt.data.len() != 8 {
				gpgobj_new_error!{GpgComplexError,"salt.len {} != 8" ,self.salt.data.len()}
			}
			cv = self.salt.encode_gpg()?;
			encv.extend(cv.iter().copied());			
		}

		if self.mode.data == 3 {
			cv = self.cnt.encode_gpg()?;
			encv.extend(cv.iter().copied());			
		}

		cv = self.seskey.encode_gpg()?;
		encv.extend(cv.iter().copied());

		retv = encode_gpgobj_header(self.matchid,self.extflag,encv.len())?;
		retv.extend(encv.iter().copied());
		Ok(retv)
	}

	fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		let mut s :String;
		if self.version.version != 4 {
			gpgobj_new_error!{GpgComplexError,"version {} != 4" ,self.version.version}
		}


		if (self.mode.data & 0x3 ) != self.mode.data {
			gpgobj_new_error!{GpgComplexError,"mode {} not in 0..3", self.mode.data}
		}

		if (self.mode.data == 3 || self.mode.data == 1 ) && self.salt.data.len() != 8 {
			gpgobj_new_error!{GpgComplexError,"salt len {} != 8",self.salt.data.len()}
		}

		s = gpgobj_format_line(tab , &format!("{} GpgSessionKey", name));
		iowriter.write(s.as_bytes())?;

		self.version.print_gpg("version", tab + 1, iowriter)?;
		s = gpgobj_format_line(tab + 1, &format!("cipheralgo {}", cipher_algo_str(self.cipheralgo.data)));
		iowriter.write(s.as_bytes())?;
		s = gpgobj_format_line(tab + 1, &format!("digalgo {}", get_digalgo_str(self.hashalgo.data)));
		iowriter.write(s.as_bytes())?;
		if self.mode.data == 3 || self.mode.data == 1 {
			self.salt.print_gpg("salt",tab + 1, iowriter)?;
		}

		if self.mode.data == 3 {
			self.cnt.print_gpg("cnt",tab + 1, iowriter)?;
		}
		self.seskey.print_gpg("seskey",tab + 1, iowriter)?;
		Ok(())
	}
}


#[gpgobj_sequence()] 
pub struct GpggpgFile {
	pub seskey :GpgSessionKey,
}