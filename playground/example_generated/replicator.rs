
#[allow(unused_imports)]
use maplit::{hashmap, hashset};

pub use reo_rs::*;
use reo_rs::building::{*, NameDef::*};
use reo_rs::Instruction::*;
use reo_rs::Term::*;

#[no_mangle]
pub extern fn reors_generated_proto_create() -> CProtoHandle {
    reo_rs::to_c_proto(proto_protocol1_build_rust::<isize>())
}

pub fn proto_protocol1_build_rust<T0>(
) -> ProtoHandle
where
    T0: 'static + Send + Sync + Sized + Clone,
{
    let name_defs = hashmap!{
        "a" => Port { is_putter: true, type_info: TypeInfo::of::<T0>() },
        "b" => Port { is_putter: false, type_info: TypeInfo::of::<T0>() },
        "c" => Port { is_putter: false, type_info: TypeInfo::of::<T0>() },
    };
    let rules = vec![
        RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"a", "b", "c"},
                full_mem: hashset! { },
                empty_mem: hashset! { },
            },
            ins: vec![
            ],
            output: hashmap!{
                "a" => (false, hashset!{"b", "c", }),
            }
        },
    ];
    let mem_init = MemInitial::default();
    ProtoDef {
        name_defs,
        rules
    }.build(mem_init).expect("Oh no! Reo failed to build!")
}

