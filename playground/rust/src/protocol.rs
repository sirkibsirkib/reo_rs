use maplit::{hashmap, hashset};
use reo_rs::{*, building::*};

pub fn new_fifo1() -> ProtoHandle {
    ProtoDef {
        name_defs: hashmap! {
            "A" => NameDef::Port { is_putter:true , type_info: TypeInfo::of::<isize>() },
            "B" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<isize>() },
            "M" => NameDef::Mem ( TypeInfo::of::<isize>() ),
        },
        rules: vec![
            RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {"A"},
                    full_mem:    hashset! {},
                    empty_mem:   hashset! {"M"},
                },
                ins: vec![],
                output: hashmap! { "A" => (false, hashset!{"M"}) },
            },
            RuleDef {
                state_guard: StatePredicate {
                    ready_ports: hashset! {"B"},
                    full_mem:    hashset! {"M"},
                    empty_mem:   hashset! {},
                },
                ins: vec![],
                output: hashmap! { "M" => (false, hashset!{"B"}) },
            },
        ],
    }
    .build(MemInitial::default())
    .expect("Oh no I did something wrong!")
}
