
use std::io::{Write};
use std::error::Error;

pub trait GpgOp {
	fn decode_gpg(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>>;
	fn encode_gpg(&self) -> Result<Vec<u8>, Box<dyn Error>>;
	fn print_gpg<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>>;
	fn init_gpg() -> Self;
}

