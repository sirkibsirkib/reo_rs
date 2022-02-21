use super::{building::*, BOOL_TYPE_KEY as BTK, *};
use maplit::{hashmap, hashset};
use std::thread;

const NULL_MUT: *mut u8 = core::ptr::null_mut();

lazy_static::lazy_static! {
    static ref PROTO_DEF_TRIVIAL: ProtoDef = ProtoDef::default();
    static ref PROTO_DEF_SYNC: ProtoDef = ProtoDef {
        mover_defs: vec![
            MoverDef { type_key: BTK, mover_kind: MoverKind::PutterPort },
            MoverDef { type_key: BTK, mover_kind: MoverKind::GetterPort },
        ],
        rules: vec![RuleDef {
            ready: index_set! {0,1},
            ready_and_full_mem: index_set! {},
            instructions: vec![],
            movements: vec![Movement { putter: 0, putter_retains: false, getters: index_set! {1} }],
        }],
    };
}

#[test]
fn build_trivial() {
    PROTO_DEF_TRIVIAL.build().unwrap();
}

#[test]
fn build_sync() {
    PROTO_DEF_SYNC.build().unwrap();
}

// #[test]
// fn signal_emitter() {
//     let proto_def = ProtoDef {
//         mover_defs: vec![
//             MoverDef { mover_kind: MoverKind::GetterPort, type_key: BTK },
//             MoverDef { mover_kind: MoverKind::MemoryCell, type_key: BTK },
//         ],
//         rules: vec![RuleDef {
//             instructions: vec![],
//             ready: index_set! {0,1},
//             ready_and_full_mem: index_set! {1},
//             movements: vec![Movement { putter: 1, getters: index_set! {0}, putter_retains: true }],
//         }],
//     };
//     let p = proto_def.build().unwrap();
//     println!("{:#?}", p);
//     let p = Arc::new(p);
//     unsafe { p.fill_memory_typed(1, true) }.unwrap();
//     let mut a = unsafe { Getter::claim_raw(&p, 0).unwrap() };
//     // let mut dest = false;
//     for _ in 0..3 {
//         a.get_signal();
//         // unsafe { a.get_raw(&mut dest as *mut bool as *mut u8) };
//     }
// }

/*
#[test]
fn copying_emitter() {
    static TK0: TypeKey = BOOL_TYPE_KEY;
    let proto_def = ProtoDef {
        name_defs: hashmap! {
            A => NameDef::Port { is_putter: false, type_key: TK0, },
            M => NameDef::Mem { type_key: TK0, },
        },
        rules: vec![RuleDef {
            ins: vec![],
            output: hashmap! {
                M => (true, hashset!{A}),
            },
        }],
    };
    let p = proto_def.build().unwrap();
    unsafe { p.fill_memory_typed(M, true) }.unwrap();
    let mut a = unsafe { Getter::claim_raw(&p, A).unwrap() };
    for _ in 0..5 {
        assert!(unsafe { a.get_typed::<bool>() });
    }
}

#[test]
fn bool_sink() {
    static TK0: TypeKey = BOOL_TYPE_KEY;
    let proto_def = ProtoDef {
        name_defs: hashmap! {
            A => NameDef::Port { is_putter: true, type_key: TK0, },
        },
        rules: vec![RuleDef {
            ins: vec![],
            output: hashmap! {
                A => (true, hashset!{}),
            },
        }],
    };
    let p = proto_def.build().unwrap();
    let mut a = unsafe { Putter::claim_raw(&p, A).unwrap() };
    for _ in 0..5 {
        unsafe { a.put_typed(&mut MaybeUninit::new(false)) };
    }
}

#[test]
fn a_to_b_synchronous() {
    static TK0: TypeKey = BOOL_TYPE_KEY;
    let proto_def = ProtoDef {
        name_defs: hashmap! {
            A => NameDef::Port { is_putter: true, type_key: TK0, },
            B => NameDef::Port { is_putter: false, type_key: TK0, },
        },
        rules: vec![RuleDef {
            ins: vec![],
            output: hashmap! {
                A => (false, hashset!{B}),
            },
        }],
    };
    let p = proto_def.build().unwrap();
    let (mut a, mut b) =
        unsafe { (Putter::claim_raw(&p, A).unwrap(), Getter::claim_raw(&p, B).unwrap()) };

    let handles = [
        thread::spawn(move || {
            let mut data = MaybeUninit::new(false);
            for _ in 0..5 {
                unsafe {
                    a.put_typed(&mut data);
                    *(&mut *data.as_mut_ptr()) ^= true;
                }
            }
        }),
        thread::spawn(move || {
            let mut expected = false;
            for _ in 0..5 {
                unsafe {
                    let got: bool = b.get_typed();
                    println!("got {}", got);
                    assert_eq!(got, expected);
                    expected = !expected;
                }
            }
        }),
    ];
    for h in handles {
        h.join().unwrap();
    }
}
#[test]
fn a_to_b_asynchronous() {
    static TK0: TypeKey = BOOL_TYPE_KEY;
    let proto_def = ProtoDef {
        name_defs: hashmap! {
            A => NameDef::Port { is_putter: true, type_key: TK0, },
            B => NameDef::Port { is_putter: false, type_key: TK0, },
            M => NameDef::Mem { type_key: TK0 },
        },
        rules: vec![
            RuleDef {
                ins: vec![],
                output: hashmap! {
                    A => (false, hashset!{M}),
                },
            },
            RuleDef {
                ins: vec![],
                output: hashmap! {
                    M => (false, hashset!{B}),
                },
            },
        ],
    };
    let p = proto_def.build().unwrap();
    let (mut a, mut b) =
        unsafe { (Putter::claim_raw(&p, A).unwrap(), Getter::claim_raw(&p, B).unwrap()) };

    let handles = [
        thread::spawn(move || {
            let mut data = MaybeUninit::new(false);
            for _ in 0..5 {
                unsafe {
                    a.put_typed(&mut data);
                    *(&mut *data.as_mut_ptr()) ^= true;
                }
            }
        }),
        thread::spawn(move || {
            let mut expected = false;
            for _ in 0..5 {
                unsafe {
                    let got: bool = b.get_typed();
                    println!("got {}", got);
                    assert_eq!(got, expected);
                    expected = !expected;
                }
            }
        }),
    ];
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn unsafe_main() {
    static TK0: TypeKey = BOOL_TYPE_KEY;
    let proto_def = ProtoDef {
        name_defs: hashmap! {
            A => NameDef::Port { is_putter: true, type_key: TK0, },
            B => NameDef::Mem {  type_key: TK0, },
            C => NameDef::Port { is_putter: false, type_key: TK0, },
            D => NameDef::Port { is_putter: false, type_key: TK0, },
        },
        rules: vec![
            RuleDef {
                ins: vec![],
                output: hashmap! {
                    A => (false, hashset!{B}),
                },
            },
            RuleDef {
                ins: vec![],
                output: hashmap! {
                    B => (false, hashset!{C}),
                },
            },
            RuleDef {
                ins: vec![],
                output: hashmap! {
                    B => (false, hashset!{D}),
                },
            },
        ],
    };
    let p = proto_def.build().unwrap();
    unsafe { p.fill_memory_raw(B, (&mut true) as *mut bool as *mut u8).unwrap() };

    let (mut a, mut c, mut d) = unsafe {
        (
            Putter::claim_raw(&p, A).unwrap(),
            Getter::claim_raw(&p, C).unwrap(),
            Getter::claim_raw(&p, D).unwrap(),
        )
    };

    let handles = [
        thread::spawn(move || {
            for _ in 0..3 {
                unsafe {
                    a.put_raw((&mut true) as *mut bool as *mut u8);
                }
            }
        }),
        thread::spawn(move || {
            for _ in 0..2 {
                unsafe {
                    println!("C {:?}", c.get_raw(NULL_MUT));
                }
            }
        }),
        thread::spawn(move || {
            for _ in 0..2 {
                unsafe {
                    println!("D {:?}", d.get_raw(NULL_MUT));
                }
            }
        }),
    ];
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn unsafe_call() {
    static TK0: TypeKey = BOOL_TYPE_KEY;
    let call_handle_f =
        unsafe { CallHandle::new_unary::<bool, bool>(|r, a0| *r = *a0, TK0, &[TK0]) };
    let proto_def = ProtoDef {
        name_defs: hashmap! {
            A => NameDef::Port { is_putter: true, type_key: TK0, },
            B => NameDef::Port { is_putter: false, type_key: TK0, },
            F => NameDef::Func(call_handle_f),
        },
        rules: vec![RuleDef {
            ins: vec![
                // ok
                Instruction::CreateFromCall {
                    type_key: TK0,
                    dest: M,
                    func: F,
                    args: vec![Term::Named(A)],
                },
            ],
            output: hashmap! {
                A => (false, hashset!{}),
                M => (false, hashset!{B}),
            },
        }],
    };
    let p = building::build_proto(&proto_def).unwrap();

    let (mut a, mut b) =
        unsafe { (Putter::claim_raw(&p, A).unwrap(), Getter::claim_raw(&p, B).unwrap()) };

    let handles = [
        thread::spawn(move || {
            for _ in 0..3 {
                unsafe {
                    a.put_raw((&mut true) as *mut bool as *mut u8);
                }
            }
        }),
        thread::spawn(move || {
            for _ in 0..3 {
                unsafe {
                    println!("B {:?}", b.get_raw(NULL_MUT));
                }
            }
        }),
    ];
    for h in handles {
        h.join().unwrap();
    }
}
*/
