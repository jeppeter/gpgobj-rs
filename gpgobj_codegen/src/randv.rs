
use rand::Rng;
use bytes::{BytesMut,BufMut};


const RAND_NAME_STRING :[u8; 62]= *b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";


pub (crate) fn get_random_bytes(num :u32) -> String {
	let mut retm = BytesMut::with_capacity(num as usize);
	let mut rng = rand::thread_rng();
	let mut curi :usize;

	for _i in 0..num {
		curi = rng.gen_range(0..RAND_NAME_STRING.len());
		retm.put_u8(RAND_NAME_STRING[curi]);
	}
	let a = retm.freeze();
	String::from_utf8_lossy(&a).to_string()
}
