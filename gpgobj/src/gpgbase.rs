
use super::gpgimpl::{GpgOp};
#[allow(unused_imports)]
use super::logger::{gpgobj_debug_out,gpgobj_log_get_timestamp};
use super::{gpgobj_log_trace,gpgobj_error_class,gpgobj_new_error};
use super::consts::{PUBKEY_ALGO_RSA,GPG_HEADER_EXTENSION_FLAG,GPG_EXTENSION_MASK,GPG_NORMAL_MASK,GPG_NORMAL_SHIFT,GPG_EXTHDR_MAX_CODE,GPG_EXTHDR_LEN_MASK,PKT_PUBLIC_KEY};
use num_bigint::{BigUint};
use super::strop::{gpgobj_format_line};
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

impl GpgPubKey {
    fn parse_value(&self, s :&str) -> Result<i64,Box<dyn Error>> {
        match i64::from_str_radix(s,10) {
            Ok(v) => {              
                return Ok(v);
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"parse [{}] error[{:?}]",s,e}
            }
        }
    }

    fn format_time_str(&self, year :i64, mon :i64,mday :i64,hour :i64, min :i64,sec :i64) -> String {
        return format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year,mon,mday,hour,min,sec);
    }

    fn get_time_val(&self, times :&str) -> Result<(i64,i64,i64,i64,i64,i64),Box<dyn Error>> {
        let mut year :i64;
        let mut mon :i64;
        let mut mday :i64;
        let mut hour :i64;
        let mut min :i64;
        let mut sec :i64;
        asn1obj_log_trace!("times [{}]", times);

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

        asn1obj_new_error!{Asn1ObjBaseError,"not valid [{}] times", times}

    }

    fn extract_encode_value(&self, s :&str) -> Result<(i64,i64,i64,i64,i64,i64),Box<dyn Error>> {
        let mut year :i64;
        let mut mon :i64;
        let mut mday :i64;
        let mut hour :i64;
        let mut min :i64;
        let mut sec :i64;
        let mut dt :DateTime<Utc>;

        let c :String = "^(([0-9]+)(\\.[0-9]+)?(([-\\+])([0-9]+))?([Z|X]?))$".to_string();
        let ro = Regex::new(&c);
        if ro.is_err() {
            let e = ro.err().unwrap();
            asn1obj_new_error!{Asn1ObjBaseError,"regex [{}] error[{:?}]", c,e}
        }
        let reex = ro.unwrap();
        let co = reex.captures(s);
        if co.is_none() {
            asn1obj_new_error!{Asn1ObjBaseError,"regex [{}] capture [{}] none", c,s}
        }

        asn1obj_log_trace!("encoded value [{}]",s);

        let v = co.unwrap();
        let times :String;
        let zs :String;
        let diffs :String;

        times = format!("{}",v.get(2).map_or("", |m| m.as_str()));
        if times.len() < 10 {
            asn1obj_new_error!{Asn1ObjBaseError,"[{}] first part less < 10", s}
        }

        zs = format!("{}",v.get(7).map_or("", |m| m.as_str()));
        diffs = format!("{}",v.get(4).map_or("", |m| m.as_str()));

        (year,mon,mday,hour,min,sec) = self.get_time_val(&times)?;

        if diffs.len() > 0  {
            let plusorminus :String = format!("{}",v.get(5).map_or("", |m| m.as_str()));
            let offstr :String = format!("{}",v.get(6).map_or("", |m| m.as_str()));
            if zs.len() > 0 {
                if zs == "Z" {
                    asn1obj_new_error!{Asn1ObjBaseError,"not valid time string [{}]",s} 
                }               
            }

            if offstr.len() != 4 {
                asn1obj_new_error!{Asn1ObjBaseError, "offstr [{}] != 4", offstr}
            }

            let voff = self.parse_value(&offstr[0..2])?;
            if voff > 12 {
                asn1obj_new_error!{Asn1ObjBaseError,"not valid offset [{}]",offstr}
            }

            dt = Utc.ymd(year as i32,mon as u32,mday as u32).and_hms(hour as u32,min as u32,sec as u32);
            if plusorminus == "+" {
                dt = dt - Duration::hours(voff);
            } else {
                dt = dt + Duration::hours(voff);
            }
            year = dt.year() as i64;
            mon = dt.month() as i64;
            mday = dt.day() as i64;
            hour = dt.hour() as i64;
            min = dt.minute() as i64;
            sec= dt.second() as i64;
        }

        if zs.len() != 0 {
            if zs != "Z" && zs != "X" {
                asn1obj_new_error!{Asn1ObjBaseError,"not valid time [{}]",s}
            }
        }

        Ok((year,mon,mday,hour,min,sec))


    }

    fn extract_date_value(&self,s :&str) -> Result<(i64,i64,i64,i64,i64,i64),Box<dyn Error>> {
        let c :String = "([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2})(:([0-9]{2}))?".to_string();
        let ro = Regex::new(&c);
        if ro.is_err() {
            let e = ro.err().unwrap();
            asn1obj_new_error!{Asn1ObjBaseError,"regex [{}] error[{:?}]", c,e}
        }
        let reex = ro.unwrap();
        let co = reex.captures(s);
        if co.is_none() {
            asn1obj_new_error!{Asn1ObjBaseError,"regex [{}] capture [{}] default [{}] none", c,s, ASN1_TIME_DEFAULT_STR}
        }
        let v = co.unwrap();
        if v.len() < 8 {
            asn1obj_new_error!{Asn1ObjBaseError,"regex [{}] capture [{}] default [{}] {:?} < 8", c,s, ASN1_TIME_DEFAULT_STR,v}
        }

        let year :i64;
        let mon :i64;
        let mday :i64;
        let hour :i64;
        let min :i64;
        let sec :i64;
        let mut cc :String;

        cc = format!("{}",v.get(1).map_or("", |m| m.as_str()));
        match i64::from_str_radix(&cc,10) {
            Ok(v) => {
                year = v;
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
            }
        }

        cc = format!("{}",v.get(2).map_or("", |m| m.as_str()));
        match i64::from_str_radix(&cc,10) {
            Ok(v) => {
                mon = v;
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
            }
        }

        cc = format!("{}",v.get(3).map_or("", |m| m.as_str()));
        match i64::from_str_radix(&cc,10) {
            Ok(v) => {
                mday = v;
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
            }
        }

        cc = format!("{}",v.get(4).map_or("", |m| m.as_str()));
        match i64::from_str_radix(&cc,10) {
            Ok(v) => {
                hour = v;
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
            }
        }

        cc = format!("{}",v.get(5).map_or("", |m| m.as_str()));
        match i64::from_str_radix(&cc,10) {
            Ok(v) => {
                min = v;
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
            }
        }

        cc = format!("{}", v.get(7).map_or("", |m| m.as_str()));
        if cc.len() > 0 {
            match i64::from_str_radix(&cc,10) {
                Ok(v) => {
                    sec = v;
                },
                Err(e) => {
                    asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
                }
            }
        } else {
            sec = 0;
        }

        Ok((year,mon,mday,hour,min,sec))
    }

    fn check_data_valid(&self, year :i64, mon :i64,mday :i64,hour :i64, min :i64,sec :i64) -> Result<(),Box<dyn Error>> {
        if year < 1900  ||  year > 2100 {
            asn1obj_new_error!{Asn1ObjBaseError,"year [{}] < 1900" ,year}
        }
        if mon < 1 || mon > 12 {
            asn1obj_new_error!{Asn1ObjBaseError,"mon {} not valid ", mon}
        }

        if mday < 1 || mday > 31 {
            asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid", mday}
        }

        if hour < 0 || hour > 23 {
            asn1obj_new_error!{Asn1ObjBaseError,"hour {} not valid", hour}  
        }

        if min < 0 || min > 59 {
            asn1obj_new_error!{Asn1ObjBaseError,"min {} not valid", min}
        }

        if sec < 0 || sec > 59 {
            asn1obj_new_error!{Asn1ObjBaseError,"sec {} not valid", sec}    
        }

        if (mon == 4 || mon == 6 || mon == 9 || mon == 11) && mday > 30 {
            asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}    
        }

        if mon == 2 {
            if (year % 4) != 0 && mday > 28 {
                asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}    
            } else if (year % 4) == 0 && (year % 100) != 0 && mday > 29 {
                asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}    
            } else if (year % 4) == 0 && (year % 100) == 0 && (year % 400) != 0 && mday > 28 {
                asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}    
            } else if (year % 4) == 0 && (year % 400) == 0 && mday > 29  {
                asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}
            } else if mday > 28 {
                asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}
            }           
        }
        Ok(())
    }

    pub fn set_value_str(&mut self, s :&str) -> Result<(),Box<dyn Error>> {
        let (year,mon,mday,hour,min,sec) = self.extract_date_value(s)?;
        let _ = self.check_data_valid(year,mon,mday,hour,min,sec)?;
        self.val = self.format_time_str(year,mon,mday,hour,min,sec);
        self.origval = "".to_string();
        Ok(())
    }

    pub fn get_value_str(&self) -> String {
        return format!("{}",self.val);
    }

    pub fn set_value_time(&mut self,dt :&DateTime<Utc>) -> Result<(),Box<dyn Error>> {
        let (year,mon,mday,hour,min,sec) = (dt.year(),dt.month(),dt.day(),dt.hour(),dt.minute(), dt.second());
        let _ = self.check_data_valid(year as i64,mon as i64,mday as i64,hour as i64,min as i64,sec as i64)?;
        self.val = self.format_time_str(year as i64,mon as i64,mday as i64,hour as i64,min as i64,sec as i64);
        self.origval = "".to_string();
        Ok(())
    }

    pub fn get_value_time(&self) -> Result<DateTime<Utc>,Box<dyn Error>> {
        let (year,mon,mday,hour,min,sec) = self.extract_date_value(&self.val)?;
        let dt :DateTime<Utc> = Utc.ymd(year as i32,mon as u32,mday as u32).and_hms(hour as u32,min as u32,sec as u32);
        Ok(dt)
    }
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

	fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>>{
		let mut c :String;
		c = gpgobj_format_line("{} Public Key", name);
		iowriter.write(c.as_bytes())?;


		Ok(())
	}



}