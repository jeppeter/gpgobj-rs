
use super::gpgimpl::{GpgOp};
use std::error::Error;
use super::{gpgobj_log_trace,gpgobj_error_class,gpgobj_new_error};
use super::strop::{gpgobj_format_line};
use super::logger::{gpgobj_debug_out,gpgobj_log_get_timestamp};
use super::consts::*;
use chrono::prelude::*;
use std::io::Write;
use num_bigint::{BigUint};
use num_traits::{Zero};

gpgobj_error_class!{GpgBaseError}


pub fn get_pubk_nsig_cnt(pubkalgo :u8) -> usize {
    if pubkalgo == PUBKEY_ALGO_RSA || 
    pubkalgo == PUBKEY_ALGO_RSA_E ||
    pubkalgo == PUBKEY_ALGO_RSA_S {
        return 1;
    } else if pubkalgo == PUBKEY_ALGO_DSA ||
    pubkalgo == PUBKEY_ALGO_ECDSA ||
    pubkalgo == PUBKEY_ALGO_ELGAMAL ||
    pubkalgo == PUBKEY_ALGO_EDDSA {
        return 2;
    }
    return 0;
}

pub fn get_pubk_str(pubkalgo :u8) -> String {
    let rets :String;
    match pubkalgo {
        PUBKEY_ALGO_RSA => {
            rets = format!("PUBKEY_ALGO_RSA");
        },
        PUBKEY_ALGO_RSA_E => {
            rets = format!("PUBKEY_ALGO_RSA_E");
        },
        PUBKEY_ALGO_RSA_S => {
            rets = format!("PUBKEY_ALGO_RSA_S");
        },
        PUBKEY_ALGO_DSA => {
            rets = format!("PUBKEY_ALGO_DSA");
        },
        PUBKEY_ALGO_ECDH => {
            rets= format!("PUBKEY_ALGO_ECDH");
        },
        PUBKEY_ALGO_ECDSA => {
            rets = format!("PUBKEY_ALGO_ECDSA");
        },
        PUBKEY_ALGO_ELGAMAL => {
            rets = format!("PUBKEY_ALGO_ELGAMAL");
        },
        PUBKEY_ALGO_EDDSA => {
            rets = format!("PUBKEY_ALGO_EDDSA");
        },
        _ => {
            rets = format!("unknown {}", pubkalgo);
        }
    }
    return rets;
}

pub fn cipher_algo_str(cipheralgo :u8) -> String {
    let rets :String;
    match cipheralgo {
        CIPHER_ALGO_NONE => {
            rets = format!("CIPHER_ALGO_NONE");
        },
        CIPHER_ALGO_IDEA => {
            rets = format!("CIPHER_ALGO_IDEA");
        },
        CIPHER_ALGO_3DES => {
            rets = format!("CIPHER_ALGO_3DES");
        },
        CIPHER_ALGO_CAST5 => {
            rets = format!("CIPHER_ALGO_CAST5");
        },
        CIPHER_ALGO_BLOWFISH => {
            rets = format!("CIPHER_ALGO_BLOWFISH");
        },
        CIPHER_ALGO_AES => {
            rets = format!("CIPHER_ALGO_AES");
        },
        CIPHER_ALGO_AES192 => {
            rets = format!("CIPHER_ALGO_AES192");
        },
        CIPHER_ALGO_AES256 => {
            rets = format!("CIPHER_ALGO_AES256");
        },
        CIPHER_ALGO_TWOFISH => {
            rets = format!("CIPHER_ALGO_TWOFISH");
        },
        CIPHER_ALGO_CAMELLIA128 => {
            rets = format!("CIPHER_ALGO_CAMELLIA128");
        },
        CIPHER_ALGO_CAMELLIA192 => {
            rets = format!("CIPHER_ALGO_CAMELLIA192");
        },
        CIPHER_ALGO_CAMELLIA256 => {
            rets = format!("CIPHER_ALGO_CAMELLIA256");
        },
        CIPHER_ALGO_PRIVATE10 => {
            rets = format!("CIPHER_ALGO_PRIVATE10");
        },
        _ => {
            rets = format!("unknown {}",cipheralgo);
        },
    }
    return rets;
}


pub fn get_digalgo_str(digalgo :u8) -> String {
    let rets :String;
    match digalgo {
        DIGEST_ALGO_MD5 => {
            rets = format!("DIGEST_ALGO_MD5");
        },
        DIGEST_ALGO_SHA1 => {
            rets = format!("DIGEST_ALGO_SHA1");
        },
        DIGEST_ALGO_RMD160 => {
            rets = format!("DIGEST_ALGO_RMD160");
        },
        DIGEST_ALGO_SHA256 => {
            rets = format!("DIGEST_ALGO_SHA256");
        },
        DIGEST_ALGO_SHA384 => {
            rets = format!("DIGEST_ALGO_SHA384");
        },
        DIGEST_ALGO_SHA512 => {
            rets = format!("DIGEST_ALGO_SHA512");
        },
        DIGEST_ALGO_SHA224 => {
            rets = format!("DIGEST_ALGO_SHA224");
        },
        _ => {
            rets = format!("unknown {}" ,digalgo);
        }
    }
    return rets;
}



pub fn decode_gpgobj_header(code :&[u8]) -> Result<(u8,bool,usize,usize),Box<dyn Error>> {
    let flag :u8;
    let hdrlen :usize;
    let mut tlen :usize;
    let isext :bool;

    if code.len() < 1 {
        gpgobj_new_error!{GpgBaseError,"len [{}] < 1", code.len()}
    }

    if (code[0] & GPG_HEADER_EXTENSION_FLAG) != 0 {
        flag = code[0] & GPG_EXTENSION_MASK;
        isext = true;
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
        isext = false;
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
    Ok((flag,isext,hdrlen,tlen))
}

pub fn encode_gpgobj_header(flag :u8, isext :bool , tlen :usize) -> Result<Vec<u8>,Box<dyn Error>> {
    let mut retv :Vec<u8> = Vec::new();
    let firstcode :u8;
    if isext {
        if (flag & GPG_EXTENSION_MASK) != flag {
            gpgobj_new_error!{GpgBaseError,"flag [0x{:x}] not enough [0x{:x}]",flag, GPG_EXTENSION_MASK}
        }
        firstcode = GPG_EXTHDR_LEN_MASK | (flag & GPG_EXTENSION_MASK);
        retv.push(firstcode);
        if tlen < GPG_NORMAL_MASK as usize {
            retv.push(tlen as u8);
        } else {
            let max2 :usize = 32 * 256 + GPG_NORMAL_MASK as usize;
            let mut clen = tlen;
            if clen < max2 {
                clen -= 192;
                let c = ((clen / 256) as usize + 192) as u8;
                retv.push(c);
                let c = (clen % 256) as u8;
                retv.push(c);
            } else {
                retv.push(0xff);
                retv.push(((clen >> 24) & 0xff) as u8);
                retv.push(((clen >> 16) & 0xff) as u8);
                retv.push(((clen >> 8) & 0xff) as u8);
                retv.push(((clen >> 0) & 0xff) as u8);
            }
        }
    } else {
        if (flag & GPG_NORMAL_MASK) != flag {
            gpgobj_new_error!{GpgBaseError,"flag [0x{:x}] not enough [0x{:x}]",flag, GPG_NORMAL_MASK}
        }
        firstcode = GPG_NORMAL_MASK | ((flag & GPG_NORMAL_MASK) << GPG_NORMAL_SHIFT );
        if tlen < 256 { 
            retv.push(firstcode);
            retv.push(tlen as u8);
        } else if tlen < (1 << 16) {
            retv.push(firstcode | 1);
            retv.push(((tlen >> 8) & 0xff) as u8);
            retv.push(((tlen >> 0) & 0xff) as u8);
        } else {
            retv.push(firstcode | 3);
            retv.push(((tlen >> 24) & 0xff) as u8);
            retv.push(((tlen >> 16) & 0xff) as u8);
            retv.push(((tlen >> 8) & 0xff) as u8);
            retv.push(((tlen >> 0) & 0xff) as u8);
        }
    }
    Ok(retv)
}


pub struct GpgVersion {
    pub version : u8,
}


impl GpgOp for GpgVersion {
    fn init_gpg() -> Self {
        GpgVersion {
            version : 0,
        }
    }

    fn decode_gpg(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize = 1;

        if code.len() < retv {
            gpgobj_new_error!{GpgBaseError,"[{}] < {}", code.len(),retv}
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
        //let n : NaiveDateTime=  NaiveDateTime::from_timestamp(self.timeval as i64, 0);  
        let n : NaiveDateTime=  NaiveDateTime::from_timestamp_opt(self.timeval as i64, 0).unwrap();  
        let dt :DateTime<Utc> = DateTime::from_utc(n,Utc);
        return format!("{}",dt.format("%Y-%m-%d %H:%M:%S"));
    }

    pub fn time_to_date(&self) -> DateTime<Utc> {
        //let n : NaiveDateTime=  NaiveDateTime::from_timestamp(self.timeval as i64, 0);  
        let n : NaiveDateTime=  NaiveDateTime::from_timestamp_opt(self.timeval as i64, 0).unwrap();  
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

    #[allow(deprecated)]
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


#[derive(Clone)]
pub struct GpgData {
    pub data :Vec<u8>,
}


impl GpgOp for GpgData {
    fn init_gpg() -> Self {
        GpgData {
            data : Vec::new(),
        }
    }

    fn decode_gpg(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
        self.data = Vec::new();
        for i in 0..code.len() {
            self.data.push(code[i]);
        }
        Ok(code.len())
    }

    fn encode_gpg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        return Ok(self.data.clone());
    }

    fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
        let v8 = self.data.clone();
        let mut s :String;
        let mut c :String = "".to_string();
        let mut i :usize=0;
        let mut lasti :usize = 0;
        s = gpgobj_format_line(tab, &(format!("{}: GpgData [{}:0x{:x}]", name, self.data.len(),self.data.len())));
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
        iowriter.write(s.as_bytes())?;
        Ok(())      
    }
}

#[derive(Clone)]
pub struct GpgU16 {
    pub data :u16,
}


impl GpgOp for GpgU16 {
    fn init_gpg() -> Self {
        GpgU16 {
            data : 0,
        }
    }

    fn decode_gpg(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
        if code.len() < 2 {
            gpgobj_new_error!{GpgBaseError,"code [{}] < 4", code.len()}
        }
        self.data = 0;
        self.data |= (code[0] as u16) << 8;
        self.data |= (code[1] as u16) << 0;

        Ok(2)
    }

    fn encode_gpg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retv :Vec<u8> = Vec::new();
        retv.push((self.data >> 8) as u8);
        retv.push((self.data >> 0) as u8);
        Ok(retv)
    }

    fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
        let s :String;
        s = gpgobj_format_line(tab, &format!("{} GpgU16 {} 0x{:x}",name,self.data,self.data));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}


#[derive(Clone)]
pub struct GpgU32 {
    pub data :u32,
}


impl GpgOp for GpgU32 {
    fn init_gpg() -> Self {
        GpgU32 {
            data : 0,
        }
    }

    fn decode_gpg(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
        if code.len() < 4 {
            gpgobj_new_error!{GpgBaseError,"code [{}] < 4", code.len()}
        }
        self.data = 0;
        self.data |= (code[0] as u32) << 24;
        self.data |= (code[1] as u32) << 16;
        self.data |= (code[2] as u32) << 8;
        self.data |= (code[3] as u32) << 0;

        Ok(4)
    }

    fn encode_gpg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retv :Vec<u8> = Vec::new();
        retv.push((self.data >> 24) as u8);
        retv.push((self.data >> 16) as u8);
        retv.push((self.data >> 8) as u8);
        retv.push((self.data >> 0) as u8);
        Ok(retv)
    }

    fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
        let s :String;
        s = gpgobj_format_line(tab, &format!("{} GpgU32 {} 0x{:x}",name,self.data,self.data));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}


#[derive(Clone)]
pub struct GpgU8 {
    pub data :u8,
}


impl GpgOp for GpgU8 {
    fn init_gpg() -> Self {
        GpgU8 {
            data : 0,
        }
    }

    fn decode_gpg(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
        if code.len() < 1 {
            gpgobj_new_error!{GpgBaseError,"code [{}] < 1", code.len()}
        }
        self.data = code[0];

        Ok(1)
    }

    fn encode_gpg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retv :Vec<u8> = Vec::new();
        retv.push(self.data);
        Ok(retv)
    }

    fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
        let s :String;
        s = gpgobj_format_line(tab, &format!("{} GpgU8 {} 0x{:x}",name,self.data,self.data));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}