mod protocol;

fn main() {
	let proto = protocol::new_fifo1();
	
	use reo_rs::{Putter, Getter};
	let mut a = Putter::<isize>::claim(&proto, "A").unwrap();
	let mut b = Getter::<isize>::claim(&proto, "B").unwrap();
	
	a.put(5);
	assert_eq!(b.get(), 5);
	
	a.put(2);
	assert_eq!(b.get(), 2);
	
	println!("Works!");
}