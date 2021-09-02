use std::sync::Arc;
use crate::{TypeProtected, Putter, Getter, TypedGetter, TypedPutter, TypeInfo, TypeKey, TypeMap, building::{self, ProtoDef, NameDef, RuleDef, StatePredicate}};
use std::thread;
use maplit::{hashmap, hashset};

#[test]
fn unsafe_main() {
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
	let p = building::build_proto(&proto_def, type_map).unwrap();
	unsafe { p.fill_memory_raw("B", (&mut true) as *mut bool as *mut u8).unwrap() };

    let (mut a, mut c, mut d): (Putter, Getter, Getter) = unsafe {
        (
        	Putter::claim_raw(&p, "A").unwrap(),
        	Getter::claim_raw(&p, "C").unwrap(),
        	Getter::claim_raw(&p, "D").unwrap()
        )
    };

	let handles = [
		thread::spawn(move || for _ in 0..3 { unsafe { a.put_raw((&mut true) as *mut bool as *mut u8);} }),
		thread::spawn(move || for _ in 0..2 { unsafe { println!("C {:?}", c.get_raw(None));} }),
		thread::spawn(move || for _ in 0..2 { unsafe { println!("D {:?}", d.get_raw(None));} }),
	];
	for h in handles {
		h.join().unwrap();
	}
}

#[test]
fn safe_main() {
	let type_map = TypeProtected::<TypeMap>::default();
	let type_key = TypeKey::from_type_id::<bool>();
	let proto_def = ProtoDef {
		name_defs: hashmap!{
			"A" => NameDef::Port { is_putter: true, type_key, },
			"B" => NameDef::Mem {  type_key, },
			"C" => NameDef::Port { is_putter: false, type_key, },
			"D" => NameDef::Port { is_putter: false, type_key, },
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
	let p = building::build_proto_protected(&proto_def, type_map).unwrap();
	 p.fill_memory("B", true).unwrap();

    let (mut a, mut c, mut d): (TypedPutter<bool>, TypedGetter<bool>, TypedGetter<bool>) = 
        (
        	TypedPutter::claim(&p, "A").unwrap(),
        	TypedGetter::claim(&p, "C").unwrap(),
        	TypedGetter::claim(&p, "D").unwrap()
        )
    ;

	let handles = [
		thread::spawn(move || for _ in 0..3 { a.put(true).unwrap(); }),
		thread::spawn(move || for _ in 0..2 { println!("C {:?}", c.get());}),
		thread::spawn(move || for _ in 0..2 { println!("D {:?}", d.get());}),
	];
	for h in handles {
		h.join().unwrap();
	}
}