mod protocol;

fn main() {
	let proto = protocol::new_fifo1();
	
	use reo_rs::{Putter, Getter};
	let mut a = Putter::<isize>::claim(&proto, "A").unwrap();
	let mut b = Getter::<isize>::claim(&proto, "B").unwrap();

	let to = std::time::Duration::from_millis(500);
	
	a.put(5);
	let x = b.get();
	assert_eq!(x, 5);
	println!("Sent {}", x);
	
	a.put(2);
	let x = b.get_timeout(to).unwrap();
	assert_eq!(x, 2);
	println!("Sent {}", x);

	// times out! No data is waiting!
	assert!(b.get_timeout(to).is_none()); 
	println!("Timed out!");
	
	println!("Everything went fine!");
}