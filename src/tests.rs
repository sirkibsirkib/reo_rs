use super::*;

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
    let (_, info_x) = trait_obj_read(&x);
    let (_, info_y) = trait_obj_read(&y);
    let (_, info_z) = trait_obj_read(&z);

    // string and u8 have different vtables
    assert!(info_x.0 != info_y.0);
    // y and z both use the same String vtable
    assert_eq!(info_y.0, info_z.0);
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
    fn eq(&self, _: &Self) -> bool {
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
    let (data, info) = trait_obj_read(&x);
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
    let (data, info) = trait_obj_read(&x);
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
    let (_, i) = trait_obj_read(&x);
    assert_eq!(x.my_layout(), i.get_layout());

    let x: Box<dyn PortDatum> = Box::new(true);
    let (_, i) = trait_obj_read(&x);
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
    alloc.drop_inside(new_data, type_info);
    assert_eq!(*m.lock(), 1);

    unsafe {
        let new_data2 = alloc.alloc_uninit(type_info);
        let data2: *mut Incrementor = transmute(new_data2);
        data2.write(Incrementor(m.clone()));
        new_data2
    };

    drop(alloc);
    assert_eq!(*m.lock(), 2);
}

#[test]
fn call_handle_nonary() {
    let f: fn(Outputter<String>) -> OutputToken<String> = |o| o.output(String::from("HI"));
    let ch = CallHandle::new_nonary(f);

    let mut dest_datum: MaybeUninit<String> = MaybeUninit::uninit();
    let dest: TraitData = unsafe { transmute(&mut dest_datum) };
    unsafe { ch.exec(dest, &[]) };

    let d = unsafe { dest_datum.assume_init() };
    assert_eq!(&d, "HI");
}

#[test]
fn call_handle_unary() {
    let f: fn(Outputter<u32>, &u32) -> OutputToken<u32> = |o, i| o.output(*i + 1);
    let ch = CallHandle::new_unary(f);

    let mut o: u32 = 9999;
    let dest: TraitData = unsafe { transmute(&mut o) };
    let args: [u32; 1] = [3];
    let arg_ref = unsafe { [transmute(&args[0])] };

    unsafe { ch.exec(dest, &arg_ref[..]) };
    assert_eq!(o, 4);
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
    SYNC_U32.build(MemInitial::default()).unwrap();
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
    let p = SYNC_U32.build(MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<u32>, Getter<u32>) =
        (Putter::claim(&p, "A").unwrap(), Getter::claim(&p, "B").unwrap());

    let a = std::thread::spawn(move || {
        p.put(32);
    });
    let b = std::thread::spawn(move || {
        g.get();
    });
    a.join().unwrap();
    b.join().unwrap();
}

#[test]
fn sync_put_get() {
    let p = SYNC_U32.build(MemInitial::default()).unwrap();
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
    FIFO1_STRING.build(MemInitial::default()).unwrap();
}

#[test]
fn prod_cons_claim() {
    let p = FIFO1_STRING.build(MemInitial::default()).unwrap();
    let _: (Putter<String>, Getter<String>) =
        (Putter::claim(&p, "Producer").unwrap(), Getter::claim(&p, "Consumer").unwrap());
}

#[test]
fn prod_cons_single() {
    let p = FIFO1_STRING.build(MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<String>, Getter<String>) =
        (Putter::claim(&p, "Producer").unwrap(), Getter::claim(&p, "Consumer").unwrap());
    p.put(String::from("HI!"));
    let x = g.get();
    assert_eq!(&x, "HI!");
}

#[test]
fn prod_cons_mult() {
    let p = FIFO1_STRING.build(MemInitial::default()).unwrap();
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
    let p = FIFO1_STRING.build(MemInitial::default()).unwrap();
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
            for _ in 0..10 {
                g.get_signal();
            }
        }),
    ];
    for x in handles {
        x.join().unwrap();
    }
}

#[test]
fn fifo_get_timeout() {
    let p = FIFO1_STRING.build(MemInitial::default()).unwrap();
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
    let p = FIFO1_INCREMENTOR.build(MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<Incrementor>, Getter<Incrementor>) =
        (Putter::claim(&p, "Producer").unwrap(), Getter::claim(&p, "Consumer").unwrap());
    let x = Incrementor(Arc::new(Mutex::new(0)));
    let x1 = x.clone();
    use std::thread::spawn;
    let handles = vec![
        spawn(move || {
            for _ in 0..3 {
                p.put(x1.clone());
                println!("P DONE");
            }
            // one dropped here (x1)
        }),
        spawn(move || {
            for _ in 0..2 {
                g.get();
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
            "is_neg" => NameDef::Func(CallHandle::new_unary(|o: Outputter<bool>, i: &i32| {
                o.output(*i < 0)
            })),
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
    POS_NEG.build(MemInitial::default()).unwrap();
}

#[test]
fn pos_neg_claim() {
    let p = POS_NEG.build(MemInitial::default()).unwrap();
    let _: (Putter<i32>, Getter<i32>, Getter<i32>) = (
        Putter::claim(&p, "P").unwrap(),
        Getter::claim(&p, "Cpos").unwrap(),
        Getter::claim(&p, "Cneg").unwrap(),
    );
}

#[test]
fn pos_neg_classification() {
    let p = POS_NEG.build(MemInitial::default()).unwrap();
    let (mut p, mut cpos, mut cneg): (Putter<i32>, Getter<i32>, Getter<i32>) = (
        Putter::claim(&p, "P").unwrap(),
        Getter::claim(&p, "Cpos").unwrap(),
        Getter::claim(&p, "Cneg").unwrap(),
    );

    let h = std::thread::spawn(move || {
        for i in 0i32..5 {
            p.put(i - 3);
        }
    });

    let d = Duration::from_millis(200);
    let was_pos: Vec<bool> = (0..5)
        .map(|_| {
            if cpos.get_timeout(d).is_some() {
                true
            } else if cneg.get_timeout(d).is_some() {
                false
            } else {
                panic!("hmm")
            }
        })
        .collect();
    h.join().unwrap();
    println!("{:?}", was_pos);
}

lazy_static::lazy_static! {
    static ref CREATE: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "A" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<bool>() },
        },
        rules: vec![RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"A"},
                full_mem: hashset! {},
                empty_mem: hashset! {},
            },
            ins: vec![
                Instruction::CreateFromFormula { dest: "B", term: Term::False },
            ],
            output: hashmap! {
                "B" => (false, hashset!{"A"})
            },
        }],
    };
}

#[test]
fn create_create() {
    CREATE.build(MemInitial::default()).unwrap();
}
#[test]
fn create_claim() {
    let p = CREATE.build(MemInitial::default()).unwrap();
    let _ = Getter::<bool>::claim(&p, "A").unwrap();
}

#[test]
fn create_run() {
    let p = CREATE.build(MemInitial::default()).unwrap();
    let mut g = Getter::<bool>::claim(&p, "A").unwrap();
    for _ in 0..10 {
        let x = g.get();
        println!("was {:?}", x);
        assert!(!x);
    }
}

lazy_static::lazy_static! {
    static ref MANUAL_CLONE: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "A" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<Incrementor>() },
            "f_clone" => NameDef::Func(CallHandle::new_unary(|o, i: &Incrementor| o.output(i.clone()))),
            "B" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Incrementor>() },
            "C" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Incrementor>() },
        },
        rules: vec![RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"A", "B", "C"},
                full_mem: hashset! {},
                empty_mem: hashset! {},
            },
            ins: vec![
                Instruction::CreateFromCall {
                    dest: "D" ,
                    func: "f_clone",
                    args: vec![Term::Named("A")],
                    info: TypeInfo::of::<Incrementor>()
                },
            ],
            output: hashmap! {
                "A" => (false, hashset!{"B"}),
                "D" => (false, hashset!{"C"}),
            },
        }],
    };
}

#[test]
fn manual_clone_create() {
    MANUAL_CLONE.build(MemInitial::default()).unwrap();
}

#[test]
fn manual_clone_claim() {
    let p = MANUAL_CLONE.build(MemInitial::default()).unwrap();
    let _: (Putter<Incrementor>, Getter<Incrementor>, Getter<Incrementor>) = (
        Putter::claim(&p, "A").unwrap(),
        Getter::claim(&p, "B").unwrap(),
        Getter::claim(&p, "C").unwrap(),
    );
}

#[test]
fn manual_clone_once() {
    let p = MANUAL_CLONE.build(MemInitial::default()).unwrap();
    let (mut a, mut b, mut c): (Putter<Incrementor>, Getter<Incrementor>, Getter<Incrementor>) = (
        Putter::claim(&p, "A").unwrap(),
        Getter::claim(&p, "B").unwrap(),
        Getter::claim(&p, "C").unwrap(),
    );
    let i = Incrementor(Arc::new(Mutex::new(0)));
    let ia = i.clone();

    use std::thread::spawn;
    let handles = vec![
        spawn(move || {
            for _ in 0..3 {
                a.put(ia.clone());
            }
            // ia dropped +1
        }),
        spawn(move || {
            for _ in 0..3 {
                b.get();
                // gotten dropped +3
            }
        }),
        spawn(move || {
            for _ in 0..3 {
                c.get();
                // gotten dropped +3
            }
        }),
    ];
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(*i.0.lock(), 3 + 3 + 1);
    // i dropped
}

lazy_static::lazy_static! {
    static ref EVEN_ODD: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "I" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<u32>() },
            "Oeven" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<u32>() },
            "Oodd" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<u32>() },
            "is_even" => NameDef::Func(CallHandle::new_unary(|o, i: &u32| o.output(*i %2 == 0))),
        },
        rules: vec![
            RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {"I", "Oeven"},
                    full_mem: hashset! {},
                    empty_mem: hashset! {},
                },
                ins: vec![
                    Instruction::Check { term: Term::BoolCall { func: "is_even", args: vec![Term::Named("I")] }},
                ],
                output: hashmap! { "I" => (false, hashset!{"Oeven"}) },
            },
            RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {"I", "Oodd"},
                    full_mem: hashset! {},
                    empty_mem: hashset! {},
                },
                ins: vec![
                    Instruction::Check { term: Term::Not(Box::new(
                        Term::BoolCall { func: "is_even", args: vec![Term::Named("I")]}
                    ))},
                ],
                output: hashmap! { "I" => (false, hashset!{"Oodd"}) },
            },
        ],
    };
}

#[test]
fn even_odd_build() {
    EVEN_ODD.build(MemInitial::default()).unwrap();
}

#[test]
fn even_odd_claim() {
    let p = EVEN_ODD.build(MemInitial::default()).unwrap();
    let _: (Putter<u32>, Getter<u32>, Getter<u32>) = (
        Putter::claim(&p, "I").unwrap(),
        Getter::claim(&p, "Oeven").unwrap(),
        Getter::claim(&p, "Oodd").unwrap(),
    );
}

#[test]
fn even_odd_run() {
    let p = EVEN_ODD.build(MemInitial::default()).unwrap();
    let (mut a, o_even, o_odd): (Putter<u32>, Getter<u32>, Getter<u32>) = (
        Putter::claim(&p, "I").unwrap(),
        Getter::claim(&p, "Oeven").unwrap(),
        Getter::claim(&p, "Oodd").unwrap(),
    );
    let getter_job = move |mut port: Getter<u32>, get_evens: bool| {
        for i in 0..10 {
            let is_even = i % 2 == 0;
            if is_even != get_evens {
                continue;
            }
            assert_eq!(i, port.get());
        }
    };
    use std::thread::spawn;
    let handles = vec![
        spawn(move || {
            for i in 0..10 {
                a.put(i);
            }
        }),
        spawn(move || getter_job(o_even, true)),
        spawn(move || getter_job(o_odd, false)),
    ];
    for h in handles {
        h.join().unwrap();
    }
}


lazy_static::lazy_static! {
    static ref INIT_MEM: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "C" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<Incrementor>() },
            "M" => NameDef::Mem(TypeInfo::of::<Incrementor>()),
        },
        rules: vec![
            RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {"C"},
                    full_mem: hashset! {"M"},
                    empty_mem: hashset! {},
                },
                ins: vec![],
                output: hashmap! { "M" => (false, hashset!{"C"}) },
            },
        ],
    };
}

#[test]
fn init_mem_create() {
    let i = Incrementor(Arc::new(Mutex::new(0)));
    INIT_MEM.build(MemInitial::default().with("M", i.clone())).unwrap();
    assert_eq!(*i.0.lock(), 1);
}

#[test]
fn init_mem_run() {
    let i = Incrementor(Arc::new(Mutex::new(0)));
    let p = INIT_MEM.build(MemInitial::default().with("M", i.clone())).unwrap();
    let mut port = Getter::<Incrementor>::claim(&p, "C").expect("EY");
    assert_eq!(*i.0.lock(), 0);
    port.get();
    assert_eq!(*i.0.lock(), 1);
}

lazy_static::lazy_static! {
    static ref MEM_SWAP: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "C" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<bool>() },
        },
        rules: vec![
            RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {"C"},
                    full_mem: hashset! {},
                    empty_mem: hashset! {},
                },
                ins: vec![
                    Instruction::CreateFromFormula {dest:"m0", term: Term::False},
                    Instruction::MemSwap("m0", "m1"),
                    Instruction::MemSwap("m1", "m2"),
                    Instruction::MemSwap("m2", "m3"),
                ],
                output: hashmap! { "m3" => (false, hashset!{"C"}) },
            },
        ],
    };
}

#[test]
fn mem_swap_create() {
    MEM_SWAP.build(MemInitial::default()).unwrap();
}


#[test]
fn mem_swap_run() {
    let p = MEM_SWAP.build(MemInitial::default()).unwrap();
    let mut g = Getter::<bool>::claim(&p, "C").unwrap();
    assert_eq!(g.get(), false);
    assert_eq!(g.get(), false);
    assert_eq!(g.get(), false);
}