use std::sync::Arc;
use crate::{TypeMap, building::{ProtoDef}};

use maplit::hashmap;

#[test]
fn main() {
	let type_map = Arc::new(TypeMap::default());
	let proto_def = ProtoDef {
		name_defs: hashmap!{
			// TODO
		},
		rules: vec![
			// TODO
		],
	};
	let proto = proto_def.build();
}