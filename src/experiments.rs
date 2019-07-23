use super::*;

lazy_static::lazy_static! {
    static ref FIFO_ARR: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "Producer" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Whack>() },
            "Consumer" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
            "Memory" => NameDef::Mem(TypeInfo::of::<Whack>()),
        },
        rules: vec![RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"Producer"},
                full_mem: hashset! {},
                empty_mem: hashset! {"Memory"},
            },
            ins: vec![],
            output: hashmap! {
                "Producer" => (false, hashset!{"Memory"})
            },
        },
        RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"Consumer"},
                full_mem: hashset! {"Memory"},
                empty_mem: hashset! {},
            },
            ins: vec![],
            output: hashmap! {
                "Memory" => (false, hashset!{"Consumer"})
            },
        }],
    };
}


fn one_run() -> Duration {
    let (s, r) = std::sync::mpsc::channel::<Whack>();

    // let p = FIFO_ARR.build(MemInitial::default()).unwrap();
    // let (mut s, mut r) = (
    //     Putter::<Whack>::claim(&p, "Producer").unwrap(),
    //     Getter::<Whack>::claim(&p, "Consumer").unwrap(),
    // );

    let mut taken = Duration::from_millis(0);
    for i in 0..100_000usize {
        let val = Whack([i as u8; N]);
        let t = Instant::now();
        s.send(val).unwrap();
        let _ = r.recv().unwrap();
        taken += t.elapsed();
    }
    taken
}

use std::time::{Duration, Instant};
#[test]
fn benchy1() {
    let mut taken = Duration::from_millis(0);
    const REPS: u32 = 10;
    for _ in 0..REPS {
        taken += one_run();
    }
    println!("{:?}", taken / REPS);

}



struct Whack([u8; N]);
impl PubPortDatum for Whack {
    const IS_COPY: bool = false;
    fn my_clone2(&self) -> Self {
    	// const CLONE_NANOS: u64 = 10000;
    	// std::thread::sleep(Duration::from_nanos(CLONE_NANOS));
    	// println!("CLONEY");
    	let mut x = self.0.clone();
    	for i in 0..8192_usize {
    		for val in x.iter_mut() {
	    		*val %= 11;
	    		*val *= ((i%7) as u8)+1;	
	    	}
    	}
        Self(x)
    }
    fn my_eq2(&self, _other: &Self) -> bool {
        true
    }
}



const Q: usize = 2;
const N: usize = (1<<Q)-1;
#[test]
fn benchy2() {
    let mut tot = Duration::from_millis(0);
    const REPS: u32 = 10;

    for _ in 0..REPS {
		let def = ProtoDef {
	        name_defs: hashmap! {
	            "P" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Whack>() },
	            "C0" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
	            "C1" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
	            "C2" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
	            "C3" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
	            "C4" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
	        },
	        rules: vec![
		        RuleDef {
		            state_guard: StatePredicate {
		                ready_ports: hashset! {"P", "C0", "C1", "C2", "C3", "C4"},
		                full_mem: hashset! {},
		                empty_mem: hashset! {},
		            },
		            ins: vec![],
		            output: hashmap! {
		                "P" => (false, hashset!{"C0", "C1", "C2", "C3", "C4"})
		            },
		        }
	        ],
	    };

	    let p = def.build(MemInitial::default()).unwrap();

	    const FIRINGS: u32 = 5_000  + 1;

	    use crossbeam_utils::thread;
	    let work = |name: &'static str| {
	    	let mut g = Getter::<Whack>::claim(&p, name).unwrap();
	    	for _ in 0..FIRINGS {
	    		g.get();
	    	}
	    };
		thread::scope(|s| {
			s.spawn(|_| {
				// ensure getters are ready
				// std::thread::sleep(Duration::from_millis(30)); 
	    		let mut taken = Duration::from_millis(0);
				let mut p = Putter::<Whack>::claim(&p, "P").unwrap();
				for i in 0..FIRINGS {
					let before = Instant::now();
		    		p.put(Whack([i as u8; N]));
		    		if i > 0 {
		    			taken += before.elapsed();
		    		}
		    	}
		    	tot += taken / (FIRINGS-1);
			});
			s.spawn(|_| work("C0"));
			s.spawn(|_| work("C1"));
			s.spawn(|_| work("C2"));
			s.spawn(|_| work("C3"));
			s.spawn(|_| work("C4"));
		}).unwrap();
	}
	println!("TOOK AVG {:?} ns", (tot / REPS as u32).as_nanos());
}


#[test]
fn benchy3() {
    let mut tot = Duration::from_millis(0);
    const REPS: u32 = 10;

    for _ in 0..REPS {
		let def = ProtoDef {
	        name_defs: hashmap! {
	            "P" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Whack>() },
	            "C0" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
	            "C1" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
	            "C2" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
	            "C3" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
	            "C4" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Whack>() },
	        },
	        rules: vec![
		        RuleDef {
		            state_guard: StatePredicate {
		                ready_ports: hashset! {
		                	"P",
		                	"C0",
		                	"C1",
		                	"C2",
		                	"C3",
		                	"C4",
		                },
		                full_mem: hashset! {},
		                empty_mem: hashset! {},
		            },
		            ins: vec![],
		            output: hashmap! {
		                "P" => (false, hashset!{
		                	"C0",
		                	"C1",
		                	"C2",
		                	"C3",
		                	"C4",
		               })
		            },
		        }
	        ],
	    };

	    let p = def.build(MemInitial::default()).unwrap();

	    const FIRINGS: u32 = 1_000  + 1;

	    use crossbeam_utils::thread;
	    let work = |name: &'static str| {
	    	let mut g = Getter::<Whack>::claim(&p, name).unwrap();
	    	for _ in 0..FIRINGS {
	    		g.get();
	    	}
	    };
		thread::scope(|s| {
			s.spawn(|_| {
				// ensure getters are ready
				// std::thread::sleep(Duration::from_millis(30)); 
	    		let mut taken = Duration::from_millis(0);
				let mut p = Putter::<Whack>::claim(&p, "P").unwrap();
				for i in 0..FIRINGS {
					let before = Instant::now();
		    		p.put(Whack([i as u8; N]));
		    		if i > 0 {
		    			taken += before.elapsed();
		    		}
		    	}
		    	tot += taken / (FIRINGS-1);
			});
			s.spawn(|_| work("C0"));
			s.spawn(|_| work("C1"));
			s.spawn(|_| work("C2"));
			s.spawn(|_| work("C3"));
			s.spawn(|_| work("C4"));
		}).unwrap();
	}
	println!("TOOK AVG {:?} ns", (tot / REPS as u32).as_nanos());
}