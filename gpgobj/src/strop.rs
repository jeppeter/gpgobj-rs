
pub fn gpgobj_format_line(tab :i32, s :&str) -> String {
	let mut rets :String = "".to_string();
	for _i in 0..tab {
		rets.push_str("    ");
	}
	rets.push_str(s);
	rets.push_str("\n");
	rets
}
