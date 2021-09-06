use super::{building::*, *};
use maplit::{hashmap, hashset};
use std::thread;

const A: Name = 0;
const B: Name = 1;
const C: Name = 2;
const D: Name = 3;
const F: Name = 6;
const M: Name = 13;

const NULL_MUT: *mut u8 = core::ptr::null_mut();

#[test]
fn pass_alternating() {
    static TK0: TypeKey = BOOL_TYPE_KEY;
    let proto_def = ProtoDef {
        name_defs: hashmap! {
            A => NameDef::Port { is_putter: true, type_key: TK0, },
            B => NameDef::Port { is_putter: false, type_key: TK0, },
        },
        rules: vec![RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {A, B},
                full_mem: hashset! {},
                empty_mem: hashset! {},
            },
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
fn signal_emitter() {
    static TK0: TypeKey = BOOL_TYPE_KEY;
    let proto_def = ProtoDef {
        name_defs: hashmap! {
            A => NameDef::Port { is_putter: false, type_key: TK0, },
            M => NameDef::Mem { type_key: TK0, },
        },
        rules: vec![RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {A},
                full_mem: hashset! {M},
                empty_mem: hashset! {},
            },
            ins: vec![],
            output: hashmap! {
                M => (true, hashset!{A}),
            },
        }],
    };
    let p = proto_def.build().unwrap();
    unsafe { p.fill_memory_typed(M, true) }.unwrap();
    // let mut a = unsafe { Getter::claim_raw(&p, A).unwrap() };
    // for _ in 0..5 {
    //     a.get_signal();
    // }
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
                state_guard: StatePredicate {
                    ready_ports: hashset! {A},
                    full_mem: hashset! {},
                    empty_mem: hashset! {B},
                },
                ins: vec![],
                output: hashmap! {
                    A => (false, hashset!{B}),
                },
            },
            RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {C},
                    full_mem: hashset! {B},
                    empty_mem: hashset! {},
                },
                ins: vec![],
                output: hashmap! {
                    B => (false, hashset!{C}),
                },
            },
            RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {D},
                    full_mem: hashset! {B},
                    empty_mem: hashset! {},
                },
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
            state_guard: StatePredicate {
                ready_ports: hashset! {A, B},
                full_mem: hashset! {},
                empty_mem: hashset! {},
            },
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
