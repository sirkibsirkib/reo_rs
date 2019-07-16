use super::*;
use std::collections::HashMap;

#[test]
pub fn type_info_neq() {
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u16>());
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u32>());
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u64>());
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u128>());
    assert!(TypeInfo::of::<u32>() != TypeInfo::of::<u64>());
    assert!(TypeInfo::of::<u32>() != TypeInfo::of::<u128>());
    assert!(TypeInfo::of::<u64>() != TypeInfo::of::<u128>());
}

#[test]
pub fn type_info_eq() {
    let x: Box<dyn PortDatum> = Box::new(5u8);
    let y: Box<dyn PortDatum> = Box::new(String::from("Hello"));
    let z: Box<dyn PortDatum> = Box::new(String::from("Howdy"));
    unsafe {
        let (data_x, info_x) = trait_obj_read(&x);
        let (data_y, info_y) = trait_obj_read(&y);
        let (data_z, info_z) = trait_obj_read(&z);

        // string and u8 have different vtables
        assert!(info_x.0 != info_y.0);
        // y and z both use the same String vtable
        assert_eq!(info_y.0, info_z.0);
    }
    // x,y,z dropped
}

#[test]
pub fn type_info_break() {
    let x: Box<dyn PortDatum> = Box::new(String::from("Oh hello, doggy."));
    let y: Box<dyn PortDatum> = Box::new(String::from("My, you're a tall one!"));
    let to_x: TraitObject = unsafe { transmute(x) };
    let to_y: TraitObject = unsafe { transmute(y) };
    assert_eq!(to_x.vtable, to_y.vtable);
    // assert_eq!(to_x.vtable, TypeInfo::of::<Box<dyn String>>().0);

    for data in [to_x.data, to_y.data].iter().copied() {
        let to = TraitObject { data, vtable: to_x.vtable };
        let x: Box<dyn PortDatum> = unsafe { transmute(to) };
        drop(x);
    }
}

#[test]
pub fn trait_obj_changing() {
    // task: invoke this dynamically-dispatched function using different forms
    // note: all the chosen forms have the same IN-MEMORY representation, just
    //   different ownership semantics. Arc<...> is different in some ways to Box<...>.
    // use `val` to see if it worked.

    let mut val: usize = 0;
    let mut x: Box<dyn FnMut()> = Box::new(|| val += 1);
    x(); // as owned heap allocation

    let x: &mut dyn FnMut() = unsafe { transmute(x) };
    x(); // as borrowed heap allocation

    let x: *mut dyn FnMut() = unsafe { transmute(x) };
    unsafe { (*x)() }; // as raw heap pointer

    assert_eq!(val, 3);

    // drop x again
    let x: Box<dyn FnMut()> = unsafe { transmute(x) };
    drop(x);
}

/// Note: not threadsafe at all! Need mutex for that
impl PartialEq for Incrementor {
    fn eq(&self, other: &Self) -> bool {
        true
    }
}
#[derive(Clone)]
struct Incrementor(Arc<Mutex<usize>>);
impl Drop for Incrementor {
    fn drop(&mut self) {
        *self.0.lock() += 1
    }
}

#[test]
pub fn drop_ok() {
    let m = Arc::new(Mutex::new(0));

    let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
    let y: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
    let to_x: TraitObject = unsafe { transmute(x) };
    let to_y: TraitObject = unsafe { transmute(y) };
    assert_eq!(to_x.vtable, to_y.vtable);

    // transmute does not invoke destructors
    assert_eq!(*m.lock(), 0);

    for (i, data) in [to_x.data, to_y.data].iter().copied().enumerate() {
        let vtable = to_y.vtable;
        let to = TraitObject { data, vtable };
        let x: Box<dyn PortDatum> = unsafe { transmute(to) };
        assert_eq!(*m.lock(), i);
        // destructors called as expected. memory has not been leaked
        drop(x);
        assert_eq!(*m.lock(), i + 1);
    }
}

#[test]
pub fn allocator_ok() {
    let m = Arc::new(Mutex::new(0));
    let mut alloc = Allocator::default();
    for _ in 0..5 {
        let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
        alloc.store(x);
        let x: Box<dyn PortDatum> = Box::new(String::from("hi"));
        alloc.store(x);
    }
    assert_eq!(*m.lock(), 0);
    drop(alloc);
    assert_eq!(*m.lock(), 5);
}

#[test]
pub fn allocator_drop_inside() {
    let m = Arc::new(Mutex::new(0));

    let mut alloc = Allocator::default();
    let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
    let (data, info) = unsafe { trait_obj_read(&x) };
    alloc.store(x);

    assert_eq!(*m.lock(), 0);
    // contents of x are dropped
    assert!(alloc.drop_inside(data, info));

    assert_eq!(*m.lock(), 1);

    // dropping it repeatedly fails
    assert!(!alloc.drop_inside(data, info));
    assert_eq!(*m.lock(), 1);

    drop(alloc); // box for x itself is dropped
}

#[test]
pub fn allocator_reuse() {
    let m = Arc::new(Mutex::new(0));

    let mut alloc = Allocator::default();
    let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
    let (data, info) = unsafe { trait_obj_read(&x) };
    alloc.store(x);

    assert_eq!(*m.lock(), 0);
    assert!(alloc.drop_inside(data, info));
    assert_eq!(*m.lock(), 1);

    for i in 0..5 {
        let new_data = unsafe {
            let new_data = alloc.alloc_uninit(info);
            assert_eq!(new_data, data);
            let data: *mut Incrementor = transmute(new_data);
            data.write(Incrementor(m.clone()));
            new_data
        };
        assert_eq!(*m.lock(), i + 1);
        assert!(alloc.drop_inside(new_data, info));
        assert_eq!(*m.lock(), i + 2);
    }

    drop(alloc);
    assert_eq!(*m.lock(), 6);
}

#[test]
pub fn get_layout_from_trait() {
    let m = Arc::new(Mutex::new(0));

    let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
    let layout = x.my_layout();
    assert_eq!(layout.size(), 8);
    assert_eq!(layout.align(), 8);

    let x: Box<dyn PortDatum> = Box::new(true);
    let layout = x.my_layout();
    assert_eq!(layout.size(), 1);
    assert_eq!(layout.align(), 1);
}

#[test]
pub fn get_layout_raw_eq() {
    let m = Arc::new(Mutex::new(0));

    let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
    let (_, i) = unsafe { trait_obj_read(&x) };
    assert_eq!(x.my_layout(), i.get_layout());

    let x: Box<dyn PortDatum> = Box::new(true);
    let (_, i) = unsafe { trait_obj_read(&x) };
    assert_eq!(x.my_layout(), i.get_layout());
}

#[test]
pub fn allocator_fresh_alloc() {
    let m = Arc::new(Mutex::new(0));

    let mut alloc = Allocator::default();
    let type_info = TypeInfo::of::<Incrementor>();

    let new_data = unsafe {
        let new_data = alloc.alloc_uninit(type_info);
        let data: *mut Incrementor = transmute(new_data);
        data.write(Incrementor(m.clone()));
        new_data
    };

    let new_data2 = unsafe {
        let new_data2 = alloc.alloc_uninit(type_info);
        let data2: *mut Incrementor = transmute(new_data2);
        data2.write(Incrementor(m.clone()));
        new_data2
    };

    alloc.drop_inside(new_data, type_info);
    assert_eq!(*m.lock(), 1);

    drop(alloc);
    assert_eq!(*m.lock(), 2);
}

#[test]
fn call_handle() {
    let mut x = 5;

    let b: Arc<dyn Fn(*mut u32)> = Arc::new(|dest| unsafe { dest.write(3) });
    let ch = CallHandle { func: unsafe { transmute(b) }, ret: TypeInfo::of::<u32>(), args: vec![] };

    let dest: *mut u32 = &mut x;
    let funcy: Arc<dyn Fn(*mut u32)> = unsafe { transmute(ch.func) };
    funcy(dest);

    std::mem::forget(funcy);
    println!("x={:?}", x);
}

#[test]
fn call_handle_2() {
    unsafe {
        let mut x = 5;

        let b: Arc<dyn Fn(*mut u32)> = Arc::new(|dest| dest.write(3));
        let ch = CallHandle { func: transmute(b), ret: TypeInfo::of::<u32>(), args: vec![] };

        let dest: *mut u32 = &mut x;
        let dest: TraitData = transmute(dest);
        let funcy: &Arc<dyn Fn(TraitData)> = transmute(&ch.func);
        funcy(dest);

        std::mem::forget(funcy);
        println!("x={:?}", x);
    }
}

lazy_static::lazy_static! {
    static ref SYNC_U32: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "A" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<u32>() },
            "B" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<u32>() },
        },
        rules: vec![RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"A", "B"},
                full_mem: hashset! {},
                empty_mem: hashset! {},
            },
            ins: vec![],
            output: hashmap! {
                "A" => (false, hashset!{"B"})
            },
        }],
    };
}

#[test]
fn sync_create() {
    build_proto(&SYNC_U32, MemInitial::default()).unwrap();
}

#[test]
pub fn send_sync_proto() {
    let x: MaybeUninit<ProtoCr> = MaybeUninit::uninit();
    let b = std::thread::spawn(move || {
        let y = x;
        std::mem::forget(y);
    });
    b.join().unwrap();
}

#[test]
fn sync_claim() {
    let p = build_proto(&SYNC_U32, MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<u32>, Getter<u32>) =
        (Putter::claim(&p, "A").unwrap(), Getter::claim(&p, "B").unwrap());

    let a = std::thread::spawn(move || {
        p.put(32);
    });
    let b = std::thread::spawn(move || {
        let x = g.get();
    });
    a.join().unwrap();
    b.join().unwrap();
}

#[test]
fn sync_put_get() {
    let p = build_proto(&SYNC_U32, MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<u32>, Getter<u32>) =
        (Putter::claim(&p, "A").unwrap(), Getter::claim(&p, "B").unwrap());
    use std::thread::spawn;
    let handles = vec![
        spawn(move || {
            for i in 0..10 {
                p.put(i);
            }
        }),
        spawn(move || {
            for i in 0..10 {
                let x = g.get();
                assert_eq!(x, i);
            }
        }),
    ];
    for x in handles {
        x.join().unwrap();
    }
}

lazy_static::lazy_static! {
    static ref FIFO1_STRING: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "Producer" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<String>() },
            "Consumer" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<String>() },
            "Memory" => NameDef::Mem(TypeInfo::of::<String>()),
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

#[test]
fn prod_cons_init() {
    let p = build_proto(&FIFO1_STRING, MemInitial::default()).unwrap();
}

#[test]
fn prod_cons_claim() {
    let p = build_proto(&FIFO1_STRING, MemInitial::default()).unwrap();
    let (p, g): (Putter<String>, Getter<String>) =
        (Putter::claim(&p, "Producer").unwrap(), Getter::claim(&p, "Consumer").unwrap());
}

#[test]
fn prod_cons_single() {
    let p = build_proto(&FIFO1_STRING, MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<String>, Getter<String>) =
        (Putter::claim(&p, "Producer").unwrap(), Getter::claim(&p, "Consumer").unwrap());
    println!("OK");
    p.put(String::from("HI!"));
    println!("PUT SUCCEEDED");
    println!("getting...");
    let x = g.get();
    println!("got!");
    assert_eq!(&x, "HI!");
    println!("DATUM READS {:?}", &x);
    println!("cool");
}

#[test]
fn prod_cons_mult() {
    let p = build_proto(&FIFO1_STRING, MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<String>, Getter<String>) =
        (Putter::claim(&p, "Producer").unwrap(), Getter::claim(&p, "Consumer").unwrap());
    use std::thread::spawn;
    let handles = vec![
        spawn(move || {
            for i in 0..10 {
                p.put(format!("i={}", i));
            }
        }),
        spawn(move || {
            for i in 0..10 {
                let x = g.get();
                let expected = format!("i={}", i);
                assert_eq!(expected, x);
            }
        }),
    ];
    for x in handles {
        x.join().unwrap();
    }
}

#[test]
fn fifo_get_signal() {
    let p = build_proto(&FIFO1_STRING, MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<String>, Getter<String>) =
        (Putter::claim(&p, "Producer").unwrap(), Getter::claim(&p, "Consumer").unwrap());
    use std::thread::spawn;
    let handles = vec![
        spawn(move || {
            for i in 0..10 {
                p.put(format!("i={}", i));
            }
        }),
        spawn(move || {
            for i in 0..10 {
                let x = g.get_signal();
            }
        }),
    ];
    for x in handles {
        x.join().unwrap();
    }
}

#[test]
fn fifo_get_timeout() {
    let p = build_proto(&FIFO1_STRING, MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<String>, Getter<String>) =
        (Putter::claim(&p, "Producer").unwrap(), Getter::claim(&p, "Consumer").unwrap());
    let d = Duration::from_millis(50);
    assert_eq!(false, g.get_signal_timeout(d));
    assert_eq!(false, g.get_signal_timeout(d));
    assert_eq!(false, g.get_signal_timeout(d));

    p.put(String::from("HEY"));
    assert_eq!(true, g.get_signal_timeout(d));

    assert_eq!(false, g.get_signal_timeout(d));
    assert_eq!(false, g.get_signal_timeout(d));
}

lazy_static::lazy_static! {
    static ref FIFO1_INCREMENTOR: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "Producer" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Incrementor>() },
            "Consumer" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Incrementor>() },
            "Memory" => NameDef::Mem(TypeInfo::of::<Incrementor>()),
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

#[test]
fn prod_cons_no_leak() {
    let p = build_proto(&FIFO1_INCREMENTOR, MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<Incrementor>, Getter<Incrementor>) =
        (Putter::claim(&p, "Producer").unwrap(), Getter::claim(&p, "Consumer").unwrap());
    let x = Incrementor(Arc::new(Mutex::new(0)));
    let x1 = x.clone();
    use std::thread::spawn;
    let handles = vec![
        spawn(move || {
            for i in 0..3 {
                p.put(x1.clone());
                println!("P DONE");
            }
            // one dropped here (x1)
        }),
        spawn(move || {
            for i in 0..2 {
                let gotten = g.get();
                println!("G DONE");
                // one dropped here (gotten)
            }
            // one dropped here (x)
        }),
    ];
    for h in handles {
        h.join().unwrap();
    }
    println!("FINISHING UP");
    assert_eq!(*x.0.lock(), 3);
}

#[test]
fn deref_bool() {
    let x: *mut bool = &mut true;
    let y: bool = unsafe { *x };
    assert!(y);
    let x: *mut bool = &mut false;
    let y: bool = unsafe { *x };
    assert!(!y);
}

lazy_static::lazy_static! {
    static ref POS_NEG: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "P" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<i32>() },
            "Cpos" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<i32>() },
            "Cneg" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<i32>() },
            "is_neg" => NameDef::Func(unsafe { CallHandle::new_unary_raw(Arc::new(|o: *mut bool, i: *const i32| {
                if *i < 0 {
                    *o = true;
                } else {
                    *o = false;
                }
            }))}),
        },
        rules: vec![
            RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {"P", "Cneg"},
                    full_mem: hashset! {},
                    empty_mem: hashset! {},
                },
                ins: vec![Instruction::Check { term: Term::BoolCall{ func: "is_neg", args: vec![Term::Named("P")] } }],
                output: hashmap! {
                    "P" => (false, hashset!{"Cneg"})
                },
            },
            RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {"P", "Cpos"},
                    full_mem: hashset! {},
                    empty_mem: hashset! {},
                },
                ins: vec![Instruction::Check { term: Term::Not(
                    Box::new(Term::BoolCall{ func: "is_neg", args: vec![Term::Named("P")] })
                )}],
                output: hashmap! {
                    "P" => (false, hashset!{"Cpos"})
                },
            },
        ],
    };
}

#[test]
fn pos_neg_build() {
    let p = build_proto(&POS_NEG, MemInitial::default()).unwrap();
}

#[test]
fn pos_neg_claim() {
    let p = build_proto(&POS_NEG, MemInitial::default()).unwrap();
    let (p, cpos, cneg): (Putter<i32>, Getter<i32>, Getter<i32>) = (
        Putter::claim(&p, "P").unwrap(),
        Getter::claim(&p, "Cpos").unwrap(),
        Getter::claim(&p, "Cneg").unwrap(),
    );
}


#[test]
fn pos_neg_classification() {
    let p = build_proto(&POS_NEG, MemInitial::default()).unwrap();
    let (mut p, mut cpos, mut cneg): (Putter<i32>, Getter<i32>, Getter<i32>) = (
        Putter::claim(&p, "P").unwrap(),
        Getter::claim(&p, "Cpos").unwrap(),
        Getter::claim(&p, "Cneg").unwrap(),
    );

    let h = std::thread::spawn(move || {
        for i in 0i32..5 {
            p.put(i-3);
        }
    });

    let d = Duration::from_millis(200);
    let was_pos: Vec<bool> = (0..5).map(|_| {
        if cpos.get_timeout(d).is_some() {
            true
        } else if cneg.get_timeout(d).is_some() {
            false
        } else {
            panic!("hmm")
        }
    }).collect();
    println!("{:?}", was_pos);
}
