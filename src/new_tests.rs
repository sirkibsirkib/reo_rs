use crate::TypeInfo;
use crate::{
    building::{self, NameDef, ProtoDef, RuleDef, StatePredicate},
    CallHandle, Getter, Instruction, Name, Putter, Term, TypeKey, BOOL_TYPE_KEY,
};
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
fn unsafe_main() {
    static TK0: TypeKey = BOOL_TYPE_KEY;
    println!("tk0 {:?}", TK0.0 as *const TypeInfo as usize);
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

// #[test]
// fn safe_main() {
//     let type_map = TypeProtected::<TypeMap>::default();
//     let type_key = TypeKey::from_type_id::<bool>();
//     let proto_def = ProtoDef {
//         name_defs: hashmap! {
//             A => NameDef::Port { is_putter: true, type_key, },
//             B => NameDef::Mem {  type_key, },
//             "C" => NameDef::Port { is_putter: false, type_key, },
//             "D" => NameDef::Port { is_putter: false, type_key, },
//         },
//         rules: vec![
//             RuleDef {
//                 state_guard: StatePredicate {
//                     ready_ports: hashset! {A},
//                     full_mem: hashset! {},
//                     empty_mem: hashset! {B},
//                 },
//                 ins: vec![],
//                 output: hashmap! {
//                     A => (false, hashset!{B}),
//                 },
//             },
//             RuleDef {
//                 state_guard: StatePredicate {
//                     ready_ports: hashset! {"C"},
//                     full_mem: hashset! {B},
//                     empty_mem: hashset! {},
//                 },
//                 ins: vec![],
//                 output: hashmap! {
//                     B => (false, hashset!{"C"}),
//                 },
//             },
//             RuleDef {
//                 state_guard: StatePredicate {
//                     ready_ports: hashset! {"D"},
//                     full_mem: hashset! {B},
//                     empty_mem: hashset! {},
//                 },
//                 ins: vec![],
//                 output: hashmap! {
//                     B => (false, hashset!{"D"}),
//                 },
//             },
//         ],
//     };
//     let p = building::build_proto_protected(&proto_def, type_map).unwrap();
//     p.fill_memory(B, true).unwrap();

//     let (mut a, mut c, mut d) = (
//         TypedPutter::<bool>::claim(&p, A).unwrap(),
//         TypedGetter::<bool>::claim(&p, "C").unwrap(),
//         TypedGetter::<bool>::claim(&p, "D").unwrap(),
//     );

//     let handles = [
//         thread::spawn(move || {
//             for _ in 0..3 {
//                 a.put_lossy(true);
//             }
//         }),
//         thread::spawn(move || {
//             for _ in 0..2 {
//                 println!("C {:?}", c.get());
//             }
//         }),
//         thread::spawn(move || {
//             for _ in 0..2 {
//                 println!("D {:?}", d.get());
//             }
//         }),
//     ];
//     for h in handles {
//         h.join().unwrap();
//     }
// }

#[test]
fn unsafe_call() {
    static TK0: TypeKey = BOOL_TYPE_KEY;
    let f: fn(bool) -> bool = |b| !b;
    let f = unsafe { std::mem::transmute(f) };
    let call_handle_f = unsafe { CallHandle::new_raw(f, TK0, vec![TK0]) };
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
