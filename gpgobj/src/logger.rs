

use std::env;
use std::io::{Write};
use std::fs;

use lazy_static::lazy_static;
use chrono::{Local,Timelike,Datelike};



fn _gpgobj_get_environ_var(envname :&str) -> String {
	match env::var(envname) {
		Ok(v) => {
			format!("{}",v)
		},
		Err(_e) => {
			String::from("")
		}
	}
}

struct LogVar {
	level :i32,
	nostderr : bool,
	wfile : Option<fs::File>,
}



fn gpgobj_macro_log_init(prefix :&str) -> LogVar {
	let mut getv :String;
	let mut retv :i32 = 0;
	let mut nostderr :bool = false;
	let mut coptfile :Option<fs::File> = None;
	let mut key :String;

	key = format!("{}_LEVEL", prefix);
	getv = _gpgobj_get_environ_var(&key);
	if getv.len() > 0 {
		match getv.parse::<i32>() {
			Ok(v) => {
				retv = v;
			},
			Err(e) => {
				retv = 0;
				eprintln!("can not parse [{}] error[{}]", getv,e);
			}
		}
	}

	key = format!("{}_NOSTDERR",prefix);
	getv = _gpgobj_get_environ_var(&key);
	if getv.len() > 0 {
		nostderr = true;
	}



	key = format!("{}_LOGFILE",prefix);
	getv = _gpgobj_get_environ_var(&key);
	if getv.len() > 0 {
		let fo = fs::File::create(&getv);
		if fo.is_err() {
			eprintln!("can not open [{}]", getv);		
		} else {
			coptfile = Some(fo.unwrap());
		}
	}

	return LogVar {
		level : retv,
		nostderr : nostderr,
		wfile : coptfile,		
	};
}

lazy_static! {
	static ref GPGOBJ_LOG_LEVEL : LogVar = {
		gpgobj_macro_log_init("GPGOBJ")
	};
}


pub (crate)  fn gpgobj_debug_out(level :i32, outs :&str) {
	if GPGOBJ_LOG_LEVEL.level >= level {
		let c = format!("{}\n",outs);
		if !GPGOBJ_LOG_LEVEL.nostderr {
			let _ = std::io::stderr().write_all(c.as_bytes());
		}

		if GPGOBJ_LOG_LEVEL.wfile.is_some() {
			let mut wf = GPGOBJ_LOG_LEVEL.wfile.as_ref().unwrap();
			let _ = wf.write(c.as_bytes());
		}
	}
	return;
}


pub (crate) fn gpgobj_log_get_timestamp() -> String {
	let now = Local::now();
	return format!("{}/{}/{} {}:{}:{}",now.year(),now.month(),now.day(),now.hour(),now.minute(),now.second());
}


macro_rules! gpgobj_log_error {
	($($arg:tt)+) => {
		let mut c :String= format!("<ERROR>{}[{}:{}]  ",gpgobj_log_get_timestamp(),file!(),line!());
		c.push_str(&(format!($($arg)+)[..]));
		gpgobj_debug_out(0,&c);
	}
}

#[allow(unused_macros)]
macro_rules! gpgobj_log_warn {
	($($arg:tt)+) => {
		let mut c :String= format!("<WARN>{}[{}:{}]  ",gpgobj_log_get_timestamp(),file!(),line!());
		c.push_str(&(format!($($arg)+)[..]));
		gpgobj_debug_out(10,&c);
	}
}


#[allow(unused_macros)]
macro_rules! gpgobj_log_info {
	($($arg:tt)+) => {
		let mut c :String= format!("<INFO>{}[{}:{}]  ",gpgobj_log_get_timestamp(),file!(),line!());
		c.push_str(&(format!($($arg)+)[..]));
		gpgobj_debug_out(20,&c);
	}
}

macro_rules! gpgobj_log_trace {
	($($arg:tt)+) => {
		let mut _c :String= format!("<TRACE>{}[{}:{}]  ",gpgobj_log_get_timestamp(),file!(),line!());
		_c.push_str(&(format!($($arg)+)[..]));
		gpgobj_debug_out(40, &_c);
	}
}
