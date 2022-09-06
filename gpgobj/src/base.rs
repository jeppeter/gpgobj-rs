
use super::gpgimpl::{GpgOp};
use std::error::Error;
use super::{gpgobj_log_trace,gpgobj_error_class,gpgobj_new_error};
use super::strop::{gpgobj_format_line};
use super::logger::{gpgobj_debug_out,gpgobj_log_get_timestamp};
use super::consts::{PUBKEY_ALGO_RSA,GPG_HEADER_EXTENSION_FLAG,GPG_EXTENSION_MASK,GPG_NORMAL_MASK,GPG_NORMAL_SHIFT,GPG_EXTHDR_MAX_CODE,GPG_EXTHDR_LEN_MASK};
use super::consts::{PUBKEY_ALGO_RSA_E,PUBKEY_ALGO_RSA_S,PUBKEY_ALGO_ELGAMAL_E,PUBKEY_ALGO_DSA,PUBKEY_ALGO_ECDH,PUBKEY_ALGO_ECDSA,PUBKEY_ALGO_ELGAMAL,PUBKEY_ALGO_EDDSA,PUBKEY_ALGO_PRIVATE10};
use chrono::prelude::*;
use std::io::Write;
use num_bigint::{BigUint};
use num_traits::{Zero};

gpgobj_error_class!{GpgBaseError}


pub (crate) fn decode_gpg_header(code :&[u8]) -> Result<(u8,usize,usize),Box<dyn Error>> {
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


pub struct GpgVersion {
	pub version : u8,
}


impl GpgOp for GpgVersion {
	fn init_gpg() -> Self {
		GpgVersion {
			version : 4,
		}
	}

	fn decode_gpg(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let retv :usize = 1;

		if code.len() < retv {
			gpgobj_new_error!{GpgBaseError,"[{}] < {}", code.len(),retv}
		}		
		if code[0] != 4 && code[0] != 0 {
			gpgobj_new_error!{GpgBaseError,"version [{}] not valid", code[0]}
		}
		self.version = code[0];
		Ok(retv)
	}

	fn encode_gpg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		retv.push(self.version);
		Ok(retv)
	}

	fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		let c = gpgobj_format_line(tab,&format!("{} version {}",name,self.version));
		iowriter.write(c.as_bytes())?;
		Ok(())
	}
}


pub struct GpgEncAlgorithm {
	algo : u8,
}

impl GpgEncAlgorithm {
	pub fn algo_to_str(&self) -> String {
		let s :String;
		match self.algo {
			PUBKEY_ALGO_RSA => {
				s = format!("PUBKEY_ALGO_RSA");
			},
			PUBKEY_ALGO_RSA_E => {
				s = format!("PUBKEY_ALGO_RSA_E");
			},
			PUBKEY_ALGO_RSA_S => {
				s = format!("PUBKEY_ALGO_RSA_S");
			},
			PUBKEY_ALGO_ELGAMAL_E => {
				s = format!("PUBKEY_ALGO_ELGAMAL_E");
			},
			PUBKEY_ALGO_DSA => {
				s = format!("PUBKEY_ALGO_DSA");
			},
			PUBKEY_ALGO_ECDH => {
				s = format!("PUBKEY_ALGO_ECDH");
			},
			PUBKEY_ALGO_ECDSA => {
				s = format!("PUBKEY_ALGO_ECDSA");
			},
			PUBKEY_ALGO_ELGAMAL => {
				s = format!("PUBKEY_ALGO_ELGAMAL");
			},
			PUBKEY_ALGO_EDDSA => {
				s =format!("PUBKEY_ALGO_EDDSA");
			},
			PUBKEY_ALGO_PRIVATE10 => {
				s = format!("PUBKEY_ALGO_PRIVATE10");
			},
			_ => {
				s = format!("unknown enc algorithm {}", self.algo);
			}
		}
		return s;
	}
	
	pub fn set_algo(&mut self, algo:u8) -> Result<(),Box<dyn Error>> {
		if algo == PUBKEY_ALGO_RSA || algo == PUBKEY_ALGO_RSA_E || algo == PUBKEY_ALGO_RSA_S || 
			algo == PUBKEY_ALGO_ELGAMAL_E || algo == PUBKEY_ALGO_DSA || algo == PUBKEY_ALGO_ECDH || 
			algo == PUBKEY_ALGO_ECDSA || algo == PUBKEY_ALGO_ELGAMAL || algo == PUBKEY_ALGO_EDDSA ||
			algo == PUBKEY_ALGO_PRIVATE10{
				self.algo = algo;
		}else {
			gpgobj_new_error!{GpgBaseError,"not valid algo {}",algo};
		}
		Ok(())
	}
}


impl GpgOp for GpgEncAlgorithm {
	fn init_gpg() -> Self {
		GpgEncAlgorithm {
			algo : PUBKEY_ALGO_RSA,
		}
	}

	fn decode_gpg(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let retv :usize = 1;

		if code.len() < retv {
			gpgobj_new_error!{GpgBaseError,"[{}] < {}", code.len(),retv}
		}		
		self.algo = code[0];
		Ok(retv)
	}

	fn encode_gpg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		retv.push(self.algo);
		Ok(retv)
	}

	fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		let c = gpgobj_format_line(tab,&format!("{} algo {}",name,self.algo_to_str()));
		iowriter.write(c.as_bytes())?;
		Ok(())
	}
}


pub struct GpgTime {
	timeval :u32,
}

impl GpgTime {
	pub fn time_to_str(&self) -> String {
		let n : NaiveDateTime=  NaiveDateTime::from_timestamp(self.timeval as i64, 0);	
		let dt :DateTime<Utc> = DateTime::from_utc(n,Utc);
		return format!("{}",dt.format("%Y-%m-%d %H:%M:%S"));
	}

	pub fn time_to_date(&self) -> DateTime<Utc> {
		let n : NaiveDateTime=  NaiveDateTime::from_timestamp(self.timeval as i64, 0);	
		let dt :DateTime<Utc> = DateTime::from_utc(n,Utc);
		return dt;		
	}

    fn parse_value(&self, s :&str) -> Result<i64,Box<dyn Error>> {
        match i64::from_str_radix(s,10) {
            Ok(v) => {              
                return Ok(v);
            },
            Err(e) => {
                gpgobj_new_error!{GpgBaseError,"parse [{}] error[{:?}]",s,e}
            }
        }
    }

    fn check_data_valid(&self, year :i64, mon :i64,mday :i64,hour :i64, min :i64,sec :i64) -> Result<(),Box<dyn Error>> {
        if year < 1900  ||  year > 2100 {
            gpgobj_new_error!{GpgBaseError,"year [{}] < 1900" ,year}
        }
        if mon < 1 || mon > 12 {
            gpgobj_new_error!{GpgBaseError,"mon {} not valid ", mon}
        }

        if mday < 1 || mday > 31 {
            gpgobj_new_error!{GpgBaseError,"mday {} not valid", mday}
        }

        if hour < 0 || hour > 23 {
            gpgobj_new_error!{GpgBaseError,"hour {} not valid", hour}  
        }

        if min < 0 || min > 59 {
            gpgobj_new_error!{GpgBaseError,"min {} not valid", min}
        }

        if sec < 0 || sec > 59 {
            gpgobj_new_error!{GpgBaseError,"sec {} not valid", sec}    
        }

        if (mon == 4 || mon == 6 || mon == 9 || mon == 11) && mday > 30 {
            gpgobj_new_error!{GpgBaseError,"mday {} not valid in mon {}", mday,mon}    
        }

        if mon == 2 {
            if (year % 4) != 0 && mday > 28 {
                gpgobj_new_error!{GpgBaseError,"mday {} not valid in mon {}", mday,mon}    
            } else if (year % 4) == 0 && (year % 100) != 0 && mday > 29 {
                gpgobj_new_error!{GpgBaseError,"mday {} not valid in mon {}", mday,mon}    
            } else if (year % 4) == 0 && (year % 100) == 0 && (year % 400) != 0 && mday > 28 {
                gpgobj_new_error!{GpgBaseError,"mday {} not valid in mon {}", mday,mon}    
            } else if (year % 4) == 0 && (year % 400) == 0 && mday > 29  {
                gpgobj_new_error!{GpgBaseError,"mday {} not valid in mon {}", mday,mon}
            } else if mday > 28 {
                gpgobj_new_error!{GpgBaseError,"mday {} not valid in mon {}", mday,mon}
            }           
        }
        Ok(())
    }


    fn get_time_val(&self, times :&str) -> Result<(i64,i64,i64,i64,i64,i64),Box<dyn Error>> {
        let mut year :i64;
        let mut mon :i64;
        let mut mday :i64;
        let mut hour :i64;
        let mut min :i64;
        let mut sec :i64;
        gpgobj_log_trace!("times [{}]", times);

        if times.len() == 10 {
            year = self.parse_value(&times[0..4])?;
            mon = self.parse_value(&times[4..6])?;
            mday = self.parse_value(&times[6..8])?;
            hour = self.parse_value(&times[8..10])?;
            min = 0;
            sec = 0;
            let ov = self.check_data_valid(year,mon,mday,hour,min,sec);
            if ov.is_ok() {
                return Ok((year,mon,mday,hour,min,sec));
            }

            /**/
            year = self.parse_value(&times[0..2])?;
            if year < 70 {
                year += 2000; 
            } else {
                year += 1900;
            }
            mon = self.parse_value(&times[2..4])?;
            mday = self.parse_value(&times[4..6])?;
            hour = self.parse_value(&times[6..8])?;
            min = self.parse_value(&times[8..10])?;
            sec = 0;
            let ov = self.check_data_valid(year,mon,mday,hour,min,sec);
            if ov.is_err() {
                let e = ov.err().unwrap();
                return Err(e);
            }
            return Ok((year,mon,mday,hour,min,sec));
        } 

        if times.len() == 12 {
            year = self.parse_value(&times[0..4])?;
            mon = self.parse_value(&times[4..6])?;
            mday = self.parse_value(&times[6..8])?;
            hour = self.parse_value(&times[8..10])?;
            min = self.parse_value(&times[10..12])?;
            sec = 0;
            let ov = self.check_data_valid(year,mon,mday,hour,min,sec);
            if ov.is_ok() {
                return Ok((year,mon,mday,hour,min,sec));
            }

            /**/
            year = self.parse_value(&times[0..2])?;
            if year < 70 {
                year += 2000; 
            } else {
                year += 1900;
            }
            mon = self.parse_value(&times[2..4])?;
            mday = self.parse_value(&times[4..6])?;
            hour = self.parse_value(&times[6..8])?;
            min = self.parse_value(&times[8..10])?;
            sec = self.parse_value(&times[10..12])?;
            let ov = self.check_data_valid(year,mon,mday,hour,min,sec);
            if ov.is_err() {
                let e = ov.err().unwrap();
                return Err(e);
            }
            return Ok((year,mon,mday,hour,min,sec));
        }

        if times.len() >= 14 {
            year = self.parse_value(&times[0..4])?;
            mon = self.parse_value(&times[4..6])?;
            mday = self.parse_value(&times[6..8])?;
            hour = self.parse_value(&times[8..10])?;
            min = self.parse_value(&times[10..12])?;
            sec = self.parse_value(&times[12..14])?;
            let ov = self.check_data_valid(year,mon,mday,hour,min,sec);
            if ov.is_err() {
                let e = ov.err().unwrap();
                return Err(e);
            }
            return Ok((year,mon,mday,hour,min,sec));
        }

        gpgobj_new_error!{GpgBaseError,"not valid [{}] times", times}
    }

    pub fn date_to_time(&mut self,dt :&DateTime<Utc>) -> Result<(),Box<dyn Error>> {
		let s = format!("{}",dt.format("%s"));
		let iv = self.parse_value(&s)?;
		self.timeval = iv as u32;
		Ok(())
    }

    pub fn str_to_time(&mut self, s :&str) -> Result<(),Box<dyn Error>> {
    	let (year,mon,mday,hour,min,sec) = self.get_time_val(s)?;
    	self.check_data_valid(year,mon,mday,hour,min,sec)?;
    	let dt :DateTime<Utc>= Utc.ymd(year as i32,mon as u32,mday as u32).and_hms(hour as u32,min as u32,sec as u32);
    	return self.date_to_time(&dt);
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

#[derive(Clone)]
pub struct GpgBigNum {
	pub num :BigUint,
}


impl GpgOp for GpgBigNum {
	fn init_gpg() -> Self {
		GpgBigNum {
			num : Zero::zero(),
		}
	}

	fn decode_gpg(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut clen :usize = 0;
		if code.len() < 2 {
			gpgobj_new_error!{GpgBaseError,"need at least 2 len"}
		}

		clen |= (code[0] as usize )<< 8;
		clen |= code[1] as usize;
		clen += 7;
		clen = clen / 8;

		if code.len() < (2 + clen) {
			gpgobj_new_error!{GpgBaseError,"code {} < 2 + {}" , code.len() , clen}
		}


		self.num = BigUint::from_bytes_be(&code[2..(2+clen)]);
		Ok(2 + clen)
	}

	fn encode_gpg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv : Vec<u8> = Vec::new();
		let v8 :Vec<u8>;
		let mut clen :usize;
		let mut idx : i32 = 7;

		v8 = self.num.to_bytes_be();
		clen = v8.len();
		clen *= 8;
		clen -= 8;

		if clen > 0 {
			if v8[0] == 0 {
				clen -= 7;
			} else {
				while idx >= 0 {
					if (v8[0] & (1u8 << idx)) != 0 {
						clen += idx as usize;
						break;
					}
					idx -= 1;
				}
			}
		}

		retv.push(((clen >> 8) & 0xff) as u8);
		retv.push(((clen >> 0) & 0xff) as u8);
		for i in 0..v8.len() {
			retv.push(v8[i]);
		}
		Ok(retv)
	}

	fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
        let v8 = self.num.to_bytes_be();
        let mut s :String;
        if v8.len() < 8 {
            s = gpgobj_format_line(tab, &(format!("{}: GpgBigNum 0x{:08x}", name, self.num)));
        } else {
            let mut c :String = "".to_string();
            let mut i :usize=0;
            let mut lasti :usize = 0;
            s = gpgobj_format_line(tab, &(format!("{}: GpgBigNum", name)));
            while i < v8.len() {
                if (i %16) == 0 {
                    if i > 0 {
                        c.push_str("    ");
                        while lasti != i {
                            if v8[lasti] >= 0x20 && v8[lasti] <= 0x7e {
                                c.push( v8[lasti] as char);
                            } else {
                                c.push_str(".");
                            }
                            lasti += 1;
                        }
                        s.push_str(&gpgobj_format_line(tab + 1, &format!( "{}",c)));
                        c = "".to_string();
                    }
                    lasti = i;
                }
                if lasti != i {
                    c.push_str(":");
                }               
                c.push_str(&format!("{:02x}",v8[i]));
                i += 1;
            }
            if lasti != i {
                while (i%16) != 0 {
                    c.push_str("   ");
                    i += 1;
                }
                c.push_str("    ");
                while lasti < v8.len() {
                    if v8[lasti] >= 0x20 && v8[lasti] <= 0x7e {
                        c.push( v8[lasti] as char);
                    } else {
                        c.push_str(".");
                    }
                    lasti += 1;                    
                }
            }

            if c.len() > 0 {
                s.push_str(&gpgobj_format_line(tab + 1, &format!("{}",c)));
            }
        }
        iowriter.write(s.as_bytes())?;
        Ok(())		
	}
}
