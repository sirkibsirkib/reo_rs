#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]

mod funcbending;
use funcbending::*;

type Ptr = *mut u8;
pub struct TypeInfo {}
impl TypeInfo {
    fn of<T>() -> Self {
        unimplemented!()
    }
    fn exec_partial_eq(&self, a: Ptr, b: Ptr) -> bool {
        true // TODO
    }
}


type FuncId = usize;
mod outer {
use std::any::Any;
use std::mem::ManuallyDrop;
use super::*;
    pub enum PortKind {
        Putter,
        Getter,
    }

    // PROTECTED THINGY 1: MEMORY INITIALIZER
    // struct InitializedMemory {
    // 	// CONTENTS PRIVATE
    // 	data: HashMap<Name, (TypeId, Box<u8>)>,
    // }

    // // PROTECTED THINGY 2: FUNCTION DEFINER
    // struct DefinedFunctions {
    // 	data: HashMap<Name, CallHandle>,
    // }

	use crate::Instruction;
    use crate::Term;
    use crate::TypeInfo;
    use std::any::TypeId;
    use std::collections::{HashMap, HashSet};


    pub enum MemDef {
    	Initialized(Box<dyn PortDatum>),
    	Uninitialized(TypeId),
    }

    pub enum NameDef {
    	Port{ is_putter: bool, type_id: TypeId }, 
    	Mem(MemDef),
    	Func(CallHandle),
    }

    pub struct Proto {
    	pub name_defs: HashMap<Name, NameDef>,
        pub info: HashMap<TypeId, TypeInfo>,
        pub rules: Vec<Rule>,
    }

    pub struct RulePremise {
        pub ready_ports: HashSet<Name>,
        pub full_mem: HashSet<Name>,
        pub empty_mem: HashSet<Name>,
    }
    pub struct Rule {
        pub premise: RulePremise,
        pub ins: Vec<Instruction<Name, Name>>,
        pub output: HashMap<Name, HashSet<Name>>,
    }
    pub struct Store {
        pub name: Name,
        pub term: Term<Name>,
    }
    pub type Name = &'static str;
}

pub enum Term<I> {
    True,                         // returns bool
    False,                        // returns bool
    Not(Box<Self>),               // returns bool
    And(Vec<Self>),               // returns bool
    Or(Vec<Self>),                // returns bool
    IsEq(TypeId, Box<[Self; 2]>), // returns bool
    Named(I),                     // type of I
}

pub enum Instruction<I, F> {
    CreateFromFormula {
        dest: I,
        term: Term<I>,
    },
    CreateFromCall {
        dest: I,
        func: F,
        args: Vec<Term<I>>,
    },
    Check {
        term: Term<I>,
    },
}

use outer::Name;


pub enum ProtoBuildError {
    UnavailableData { name: Name, rule_index: usize },
    InstructionHasSideEffects { name: Name, rule_index: usize },
    DuplicateNameDef { name: Name }, 
    MemoryNotInitialized { name: Name },
}

mod inner {
	use crate::*;
use maplit::{hashmap, hashset};

	fn data_ptr_of(x: &Box<dyn PortDatum>) -> Ptr {
		let converted: &(Ptr, Ptr) = unsafe {transmute(x)};
		converted.0
	}

	pub enum Space {
		PoPu(PutterSpace, MsgBox),
		PoGe(MsgBox),
		Memo(PutterSpace),
		Temp(PutterSpace),
	}
	struct MsgBox;

	pub trait Initializer {
	    fn initialize(&mut self, name: Name, o: &mut Oathkeeper) -> Option<OathKeptToken>;
	}
	pub enum OathKeptToken {}
	pub struct Oathkeeper {
	    name: Name,
	    type_id: TypeId,
	    dest: *mut u8,
	}
	fn build_proto<I: Initializer>(
	    p: outer::Proto,
	    i: &mut I,
	) -> Result<inner::Proto, ProtoBuildError> {
	    use crate::ProtoBuildError::*;
	    use outer::{NameDef, MemDef};

	    let mut spaces = vec![];
	    let mut name_mapping = BidirMap::new();
	    let mut unclaimed = hashmap!{};
	    let mut rules = vec![];
	    let mut storage = vec![]; // TODO
	    let info = p.info;

	    for (name, def) in p.name_defs {
	    	let id = spaces.len();
	    	name_mapping.insert(name, id);
	    	let space = match def {
	    		NameDef::Port { is_putter, type_id } => {
	    			unclaimed.insert(name, (is_putter, type_id));
	    			let ps = PutterSpace::new(std::ptr::null_mut(), type_id);
	    			Space::PoPu(ps, MsgBox)
	    		},
	    		NameDef::Mem(mem_def) => {
	    			let (ptr, type_id) = match mem_def {
	    				MemDef::Initialized(bx) => {
	    					let q = (data_ptr_of(&bx), bx.type_id());
	    					storage.push(bx);
	    					q
	    				},
	    				MemDef::Uninitialized(type_id) => {
	    					(std::ptr::null_mut(), type_id)
	    				}
	    			};
	    			Space::Memo(PutterSpace::new(ptr, type_id))
	    		},
	    		NameDef::Func(call_handle) => {
	    			unimplemented!()
	    		},
	    	};
	    	spaces.push(space);
	    }
	    // temp vars
	    let mut temp_name_2_id = hashmap!{};
	    let mut available_resources = hashset!{};


	    let rules = p.rules.iter().map(|rule| {
	    	let ready_ports = hashset!{};
	    	let full_mem = hashset!{};
	    	let empty_mem = hashset!{};
	    	Ok(inner::Rule {
		        ready_ports,
		        full_mem,
		        empty_mem,
		        ins: vec![],
		        output: vec![],
	    	})
	    }).collect::<Result<_, ProtoBuildError>>()?;

	    let allocator = Allocator {};
	    let mem = BitSet::default();
	    let ready = BitSet::default();
	    Ok(
	    	Proto {
	    		r: ProtoR {
	    			rules,
	    			spaces,
	    			info,
	    			name_mapping,
	    		},
	    		cr: ProtoCr {
	    			unclaimed,
	    			allocator,
	    			mem, 
	    			ready,
	    		}
	    	}
	    )
	}

    // invariant. ALL contained bitsets have same length
    use crate::outer::Name;
    use crate::outer::PortKind;
    use crate::Instruction;
    use crate::Ptr;
    use crate::Term;
    use bidir_map::BidirMap;
    use std::any::TypeId;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::mem::transmute;
    use std::sync::atomic::AtomicPtr;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::Arc;

    use core::sync::atomic::AtomicBool;

    use crate::TypeInfo;

    pub struct Proto {
        cr: ProtoCr,
        r: ProtoR,
    }

    struct ProtoR {
        rules: Vec<Rule>,
        spaces: Vec<Space>,
        info: HashMap<TypeId, TypeInfo>,
        name_mapping: BidirMap<Name, LocId>,
    }

    struct ProtoCr {
        unclaimed: HashMap<LocId, (PortKind, TypeId)>,
        ready: BitSet,
        mem: BitSet,
        allocator: Allocator,
    }

    struct Allocator {

    }

    struct Rendesvous {
        countdown: AtomicUsize,
        moved: AtomicBool,
    }
    struct PutterSpace {
        ptr: AtomicPtr<u8>,
        type_id: TypeId,
        rendesvous: Rendesvous,
    }
    impl PutterSpace {
    	fn new(ptr: Ptr, type_id: TypeId) -> Self {
	        PutterSpace {
	    		ptr: AtomicPtr::new(ptr),
	    		type_id,
	    		rendesvous: Rendesvous {
	    			countdown: 0.into(),
	    			moved: false.into(),
	    		},
	    	}
    	}
    }

    struct Rule {
        ready_ports: BitSet,
        full_mem: BitSet,
        empty_mem: BitSet,
        ins: Vec<Instruction<LocId, FuncId>>, // dummy
        output: Vec<(LocId, Vec<LocId>)>,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
    struct LocId(usize);
    impl LocId {
        const TEMP_FLAG: usize = 1 << 63;
        fn new(persistent: bool, value: usize) -> Self {
            let me = LocId(value);
            if persistent != me.persistent() {
                panic!("Cannot represent this identifier!");
            }
            me
        }
        fn persistent(self) -> bool {
            self.0 & Self::TEMP_FLAG == 0
        }
    }
    type BitSet = HashSet<LocId>;

    #[inline]
    fn bool_to_ptr(x: bool) -> Ptr {
        unsafe {
            transmute(if x {
                &mut true as *mut bool
            } else {
                &mut false as *mut bool
            })
        }
    }

    fn eval_ptr(term: &Term<LocId>, r: &ProtoR) -> Ptr {
        use Term::*;
        match term {
            // NOT NECESSARILY BOOL
            Named(i) => r.spaces[i.0].ptr.load(SeqCst),
            // MUST BE BOOL
            True => bool_to_ptr(true),
            False => bool_to_ptr(false),
            Not(t) => bool_to_ptr(!eval_bool(t, r)),
            And(ts) => bool_to_ptr(ts.iter().all(|t| eval_bool(t, r))),
            Or(ts) => bool_to_ptr(ts.iter().any(|t| eval_bool(t, r))),
            IsEq(tid, terms) => {
                let ptr0 = eval_ptr(&terms[0], r);
                let ptr1 = eval_ptr(&terms[1], r);
                let info = r.info.get(tid).expect("BAD");
                bool_to_ptr(info.exec_partial_eq(ptr0, ptr1))
            }
        }
    }
    #[inline]
    fn ptr_to_bool(x: Ptr) -> bool {
        let x: *mut bool = unsafe { transmute(x) };
        unsafe { *x }
    }

    fn eval_bool(term: &Term<LocId>, r: &ProtoR) -> bool {
        use Term::*;
        match term {
            // PTR points to BOOL
            Named(i) => ptr_to_bool(r.spaces[i.0].ptr.load(SeqCst)),
            // INHERENTLY BOOL
            True => true,
            False => false,
            Not(t) => !eval_bool(t, r),
            And(ts) => ts.iter().all(|t| eval_bool(t, r)),
            Or(ts) => ts.iter().any(|t| eval_bool(t, r)),
            IsEq(tid, terms) => {
                let ptr0 = eval_ptr(&terms[0], r);
                let ptr1 = eval_ptr(&terms[1], r);
                let info = r.info.get(tid).expect("BAD");
                info.exec_partial_eq(ptr0, ptr1)
            }
        }
    }
}


trait PortDatum {
	// const IS_COPY: bool;
	// const TYPE_ID: TypeId;
	fn type_id(&self) -> TypeId;
	fn clone(&self) -> Self where Self: Sized ;
	fn partial_eq(&self, other: &Self) -> bool where Self: Sized ;
	fn do_drop(&mut self);
}

impl<T: 'static + Copy + PartialEq> PortDatum for T {
	fn type_id(&self) -> TypeId {
		TypeId::of::<T>()
	}
	fn clone(&self) -> Self where Self: Sized {
		*self
	}
	fn partial_eq(&self, other: &Self) -> bool where Self: Sized {
		self == other
	}
	fn do_drop(&mut self) {}
}

use maplit::{hashmap, hashset};
use parking_lot::Mutex;
use std::any::TypeId;
use std::collections::HashSet;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::sync::Arc;

fn main() {
    use outer::*;
    use Instruction::*;
    use PortKind::*;
    use Term::*;

    let proto = Proto {
    	info: hashmap!{
    		TypeId::of::<u32>() => TypeInfo::of::<u32>(),
    	},
    	name_defs: hashmap!{
    		"A" => NameDef::Port { is_putter:true, type_id: TypeId::of::<u32>() },
    		"B" => NameDef::Port { is_putter:true, type_id: TypeId::of::<u32>() },
    		"C" => NameDef::Port { is_putter:true, type_id: TypeId::of::<u32>() },
    		"D" => NameDef::Mem(MemDef::Initialized(Box::new(4u32))),
    	},
        rules: vec![
            Rule {
                premise: RulePremise {
                    ready_ports: hashset! {"A", "B", "C"},
                    full_mem: hashset! {},
                    empty_mem: hashset! {},
                },
                ins: vec![],
                output: hashmap! {
                    "A" => hashset!{"B", "C"},
                },
            },
            Rule {
                premise: RulePremise {
                    ready_ports: hashset! {},
                    full_mem: hashset! {},
                    empty_mem: hashset! {},
                },
                ins: vec![],
                output: hashmap! {
                    "A" => hashset!{"B"},
                },
            },
        ],
    };
}
