use super::{building::*, BOOL_TYPE_KEY as BTK, *};
use maplit::{hashmap, hashset};
use std::thread;

const NULL_MUT: *mut u8 = core::ptr::null_mut();

fn u8_ptr<T>(t: &mut T) -> *mut u8 {
    t as *mut T as *mut u8
}

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
    static ref PROTO_DEF_ASYNC1: ProtoDef = ProtoDef {
        mover_defs: vec![
            MoverDef { type_key: BTK, mover_kind: MoverKind::PutterPort },
            MoverDef { type_key: BTK, mover_kind: MoverKind::MemoryCell },
            MoverDef { type_key: BTK, mover_kind: MoverKind::GetterPort },
        ],
        rules: vec![
            RuleDef {
                ready: index_set! {0,1},
                ready_and_full_mem: index_set! {},
                instructions: vec![],
                movements: vec![Movement { putter: 0, putter_retains: false, getters: index_set! {1} }],
            },
            RuleDef {
                ready: index_set! {1,2},
                ready_and_full_mem: index_set! {1},
                instructions: vec![],
                movements: vec![Movement { putter: 1, putter_retains: false, getters: index_set! {2} }],
            }
        ],
    };
    static ref PROTO_DEF_CLONE: ProtoDef = ProtoDef {
        mover_defs: vec![
            MoverDef { type_key: BTK, mover_kind: MoverKind::MemoryCell },
            MoverDef { type_key: BTK, mover_kind: MoverKind::GetterPort },
        ],
        rules: vec![RuleDef {
            ready: index_set! {0,1},
            ready_and_full_mem: index_set! {0},
            instructions: vec![],
            movements: vec![Movement { putter: 0, putter_retains: true, getters: index_set! {1} }],
        }],
    };
    static ref PROTO_DEF_ASYNC2: ProtoDef = ProtoDef {
        mover_defs: vec![
            MoverDef { type_key: BTK, mover_kind: MoverKind::PutterPort },
            MoverDef { type_key: BTK, mover_kind: MoverKind::MemoryCell },
            MoverDef { type_key: BTK, mover_kind: MoverKind::MemoryCell },
            MoverDef { type_key: BTK, mover_kind: MoverKind::GetterPort },
        ],
        rules: vec![
            RuleDef {
                ready: index_set! {0,1},
                ready_and_full_mem: index_set! {},
                instructions: vec![],
                movements: vec![Movement { putter: 0, putter_retains: false, getters: index_set! {1} }],
            },
            RuleDef {
                ready: index_set! {1,2},
                ready_and_full_mem: index_set! {1},
                instructions: vec![],
                movements: vec![Movement { putter: 1, putter_retains: false, getters: index_set! {2} }],
            },
            RuleDef {
                ready: index_set! {2,3},
                ready_and_full_mem: index_set! {2},
                instructions: vec![],
                movements: vec![Movement { putter: 2, putter_retains: false, getters: index_set! {3} }],
            },
        ],
    };
}

#[test]
fn trivial_build() {
    PROTO_DEF_TRIVIAL.build().unwrap();
}

#[test]
fn sync_build() {
    PROTO_DEF_SYNC.build().unwrap();
}

#[test]
fn sync_claim() {
    let proto = Arc::new(PROTO_DEF_SYNC.build().unwrap());
    let _ = Putter::claim(&proto, 0).unwrap();
    let _ = Putter::claim(&proto, 0).unwrap_err();
    let _ = Getter::claim(&proto, 1).unwrap();
    let _ = Getter::claim(&proto, 1).unwrap_err();
    let _ = Getter::claim(&proto, 2).unwrap_err();
}

#[test]
fn sync_round_raw() {
    let proto = Arc::new(PROTO_DEF_SYNC.build().unwrap());
    let mut p0 = Putter::claim(&proto, 0).unwrap();
    let mut p1 = Getter::claim(&proto, 1).unwrap();
    let handles = [
        thread::spawn(move || {
            unsafe { p0.put_raw(u8_ptr(&mut true)) };
        }),
        thread::spawn(move || {
            let mut data = false;
            unsafe { p1.get_raw(u8_ptr(&mut data)) };
            assert!(data);
        }),
    ];
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn sync_round_signal() {
    let proto = Arc::new(PROTO_DEF_SYNC.build().unwrap());
    let mut p0 = Putter::claim(&proto, 0).unwrap();
    let mut p1 = Getter::claim(&proto, 1).unwrap();
    let handles = [
        thread::spawn(move || {
            unsafe { p0.put_raw(u8_ptr(&mut true)) };
        }),
        thread::spawn(move || p1.get_signal()),
    ];
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn async1_build() {
    PROTO_DEF_ASYNC1.build().unwrap();
}

#[test]
fn async1_claim() {
    let proto = Arc::new(PROTO_DEF_ASYNC1.build().unwrap());
    let _ = Putter::claim(&proto, 0).unwrap();
    let _ = Putter::claim(&proto, 0).unwrap_err();
    let _ = Putter::claim(&proto, 1).unwrap_err();
    let _ = Getter::claim(&proto, 2).unwrap();
    let _ = Getter::claim(&proto, 2).unwrap_err();
    let _ = Getter::claim(&proto, 3).unwrap_err();
}

#[test]
fn async1_round_raw() {
    let proto = Arc::new(PROTO_DEF_ASYNC1.build().unwrap());
    let mut p0 = Putter::claim(&proto, 0).unwrap();
    let mut p2 = Getter::claim(&proto, 2).unwrap();
    let mut data2 = false;
    unsafe { p0.put_raw(u8_ptr(&mut true)) };
    unsafe { p2.get_raw(u8_ptr(&mut data2)) };
    assert!(data2);
}

#[test]
fn async1_round_signal() {
    let proto = Arc::new(PROTO_DEF_ASYNC1.build().unwrap());
    let mut p0 = Putter::claim(&proto, 0).unwrap();
    let mut p2 = Getter::claim(&proto, 2).unwrap();
    unsafe { p0.put_raw(u8_ptr(&mut true)) };
    p2.get_signal();
}

#[test]
fn clone_build() {
    PROTO_DEF_CLONE.build().unwrap();
}

#[test]
fn clone_claim() {
    let proto = Arc::new(PROTO_DEF_CLONE.build().unwrap());
    let _ = Putter::claim(&proto, 0).unwrap_err();
    let _ = Getter::claim(&proto, 1).unwrap();
    let _ = Putter::claim(&proto, 1).unwrap_err();
    let _ = Getter::claim(&proto, 2).unwrap_err();
    let _ = Getter::claim(&proto, 3).unwrap_err();
}

#[test]
fn clone_init() {
    let proto = PROTO_DEF_CLONE.build().unwrap();
    unsafe { proto.fill_memory_raw(0, u8_ptr(&mut true)).unwrap() }
}

#[test]
fn clone_round() {
    let proto = PROTO_DEF_CLONE.build().unwrap();
    unsafe { proto.fill_memory_raw(0, u8_ptr(&mut true)).unwrap() };
    let proto = Arc::new(proto);
    let mut p1 = Getter::claim(&proto, 1).unwrap();
    let mut data1 = false;
    unsafe { p1.get_raw(u8_ptr(&mut data1)) };
    assert!(data1);
}

#[test]
fn clone_signal() {
    let proto = PROTO_DEF_CLONE.build().unwrap();
    unsafe { proto.fill_memory_raw(0, u8_ptr(&mut true)).unwrap() };
    let proto = Arc::new(proto);
    let mut p1 = Getter::claim(&proto, 1).unwrap();
    p1.get_signal();
}
#[test]
fn async2_build() {
    PROTO_DEF_ASYNC2.build().unwrap();
}

#[test]
fn async2_claim() {
    let proto = Arc::new(PROTO_DEF_ASYNC2.build().unwrap());
    let _ = Putter::claim(&proto, 0).unwrap();
    let _ = Putter::claim(&proto, 0).unwrap_err();
    let _ = Putter::claim(&proto, 1).unwrap_err();
    let _ = Getter::claim(&proto, 2).unwrap_err();
    let _ = Getter::claim(&proto, 3).unwrap();
    let _ = Getter::claim(&proto, 3).unwrap_err();
}

#[test]
fn async2_round_raw() {
    let proto = Arc::new(PROTO_DEF_ASYNC2.build().unwrap());
    let mut p0 = Putter::claim(&proto, 0).unwrap();
    let mut p3 = Getter::claim(&proto, 3).unwrap();
    let mut data3 = false;
    unsafe { p0.put_raw(u8_ptr(&mut true)) };
    unsafe { p3.get_raw(u8_ptr(&mut data3)) };
    assert!(data3);
}

#[test]
fn async2_round_signal() {
    let proto = Arc::new(PROTO_DEF_ASYNC2.build().unwrap());
    let mut p0 = Putter::claim(&proto, 0).unwrap();
    let mut p3 = Getter::claim(&proto, 3).unwrap();
    unsafe { p0.put_raw(u8_ptr(&mut true)) };
    p3.get_signal();
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
