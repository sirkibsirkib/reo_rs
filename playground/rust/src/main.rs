use reo_rs::{Putter, Getter};
mod fifo1;

fn main() {
	// create a protocol instance
	let proto = fifo1::proto_protocol1_build_rust::<isize, isize, isize>();
	
	// claim, initialize the logical ports "A" and "B" and bind them to variables.
	/* Rust's borrowing rules will ensure only safe behavior is allowed.
	   Note that it is permitted to move port objects between threads to
	   achieve concurrency, parallelism. */
	let mut a = Putter::<isize>::claim(&proto, "A").unwrap();
	let mut b = Getter::<isize>::claim(&proto, "B").unwrap();

	let to = std::time::Duration::from_millis(500);
	
	// send the number 5 from A to B
	a.put(5);
	let x = b.get();
	assert_eq!(x, 5);
	println!("Sent {}", x);
	
	// send the number 2 from A to B, where B will consider timing out
	a.put(2);
	let x = b.get_timeout(to).unwrap();
	assert_eq!(x, 2);
	println!("Sent {}", x);

	// B tries to get data from the protocol's buffer slot but times out.
	// changing this to `b.get()` causes deadlock; `get` blocks UNTIL it succeeds.
	assert!(b.get_timeout(to).is_none()); 
	println!("Timed out!");
	
	println!("Everything went fine!");
	// {a, b, proto} go out of scope and are cleaned up safely.
}