mod protocol;

fn main() {
	let proto = protocol::new_fifo1();
	
	use reo_rs::{Putter, Getter};
	let a = Putter::<isize>::claim(&proto, "A").unwrap();
	let b = Getter::<isize>::claim(&proto, "B").unwrap();
	
	a.put(5);
	assert_eq!(b.get(), 5);
}