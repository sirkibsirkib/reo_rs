use std::sync::Arc;
use crate::{Putter, Getter, TypeInfo, TypeKey, TypeMap, building::{ProtoDef, NameDef, RuleDef, StatePredicate}};
use std::thread;
use maplit::{hashmap, hashset};

#[test]
fn main() {
	let type_map = Arc::new(TypeMap {
		type_infos: hashmap! {
			TypeKey(0) => TypeInfo::new_clone_eq::<bool>()
		},
		bool_type_key: TypeKey(0),
	});
	let proto_def = ProtoDef {
		name_defs: hashmap!{
			"A" => NameDef::Port { is_putter: true, type_key: TypeKey(0), },
			"B" => NameDef::Mem {  type_key: TypeKey(0), },
			"C" => NameDef::Port { is_putter: false, type_key: TypeKey(0), },
			"D" => NameDef::Port { is_putter: false, type_key: TypeKey(0), },
		},
		rules: vec![
			RuleDef {
				state_guard: StatePredicate {
					ready_ports: hashset!{"A"},
					full_mem: hashset!{},
					empty_mem: hashset!{"B"},
				},
				ins: vec![],
				output: hashmap!{
					"A" => (false, hashset!{"B"}),
				},
			},
			RuleDef {
				state_guard: StatePredicate {
					ready_ports: hashset!{"C"},
					full_mem: hashset!{"B"},
					empty_mem: hashset!{},
				},
				ins: vec![],
				output: hashmap!{
					"B" => (false, hashset!{"C"}),
				},
			},
			RuleDef {
				state_guard: StatePredicate {
					ready_ports: hashset!{"D"},
					full_mem: hashset!{"B"},
					empty_mem: hashset!{},
				},
				ins: vec![],
				output: hashmap!{
					"B" => (false, hashset!{"D"}),
				},
			},
		],
	};
	let p = proto_def.build(type_map).unwrap();
	unsafe { p.fill_memory("B", TypeKey(0), true) }.unwrap();

    let (mut a, mut c, mut d): (Putter<bool>, Getter<bool>, Getter<bool>) = unsafe {
        (
        	Putter::claim(&p, "A", TypeKey(0)).unwrap(),
        	Getter::claim(&p, "C", TypeKey(0)).unwrap(),
        	Getter::claim(&p, "D", TypeKey(0)).unwrap()
        )
    };

	let handles = [
		thread::spawn(move || for _ in 0..3 {a.put(true);}),
		thread::spawn(move || for _ in 0..2 {println!("C {:?}", c.get());}),
		thread::spawn(move || for _ in 0..2 {println!("D {:?}", d.get());}),
	];
	for h in handles {
		h.join().unwrap();
	}
}