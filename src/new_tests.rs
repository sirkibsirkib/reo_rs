use std::sync::Arc;
use crate::{Putter, Getter, TypeFuncs, TypeKey, TypeMap, building::{ProtoDef, NameDef, RuleDef, StatePredicate}};
use std::thread;
use maplit::{hashmap, hashset};

#[test]
fn main() {
	let type_map = Arc::new(TypeMap {
		funcs: hashmap! {
			TypeKey(0) => TypeFuncs::new_clone_eq::<bool>()
		},
		bool_type_key: TypeKey(0),
	});
	let proto_def = ProtoDef {
		name_defs: hashmap!{
			"A" => NameDef::Port { is_putter: true, type_info: TypeKey(0), },
			"B" => NameDef::Mem {  type_info: TypeKey(0), },
			"C" => NameDef::Port { is_putter: false, type_info: TypeKey(0), },
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
		],
	};
	let p = proto_def.build(type_map).unwrap();

    let (mut p, mut g): (Putter<bool>, Getter<bool>) = unsafe {
        (Putter::claim(&p, "A", TypeKey(0)).unwrap(), Getter::claim(&p, "C", TypeKey(0)).unwrap())
    };

	let handles = [
		thread::spawn(move || {p.put(true);}),
		thread::spawn(move || {println!("{:?}", g.get()); }),
	];
	for h in handles {
		h.join().unwrap();
	}
}