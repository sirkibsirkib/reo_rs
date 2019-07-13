#![feature(raw)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]
// #![allow(feature(raw))]

// mod funcbending;
// use funcbending::*;

use crate::inner::build_proto;
use std::mem::transmute;
use std::raw::TraitObject;

type Ptr = *mut ();

type FuncId = usize;
mod outer {
    use super::*;
    use crate::inner::TraitVtable;
    use std::any::Any;
    use std::mem::transmute;
    use std::mem::ManuallyDrop;
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
    use std::any::TypeId;
    use std::collections::{HashMap, HashSet};

    pub enum MemDef {
        Initialized(Box<dyn PortDatum>),
        Uninitialized(TypeId),
    }

    #[derive(Debug)]
    pub struct TypeInfo(pub(crate) TraitVtable);
    impl TypeInfo {
        pub fn of<T: PortDatum>() -> Self {
            let bogus: &T = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
            let to: &dyn PortDatum = bogus;
            let to: TraitObject = unsafe { transmute(to) };
            Self(to.vtable)
        }
    }

    pub struct CallHandle {
        func: TraitObject,
        ret: TypeId,
        args: Vec<TypeId>,
    }
    impl CallHandle {
        fn new_nonary<R: 'static>(func: Box<dyn Fn(*mut R)>) -> Self {
            CallHandle {
                func: unsafe { transmute(func) },
                ret: TypeId::of::<R>(),
                args: vec![],
            }
        }
        fn new_unary<R: 'static, A0: 'static>(func: Box<dyn Fn(*mut R, *const A0)>) -> Self {
            CallHandle {
                func: unsafe { transmute(func) },
                ret: TypeId::of::<R>(),
                args: vec![TypeId::of::<A0>()],
            }
        }
        fn new_binary<R: 'static, A0: 'static, A1: 'static>(
            func: Box<dyn Fn(*mut R, *const A0, *const A1)>,
        ) -> Self {
            CallHandle {
                func: unsafe { transmute(func) },
                ret: TypeId::of::<R>(),
                args: vec![TypeId::of::<A0>(), TypeId::of::<A1>()],
            }
        }
        fn new_ternary<R: 'static, A0: 'static, A1: 'static, A2: 'static>(
            func: Box<dyn Fn(*mut R, *const A0, *const A1, *const A2)>,
        ) -> Self {
            CallHandle {
                func: unsafe { transmute(func) },
                ret: TypeId::of::<R>(),
                args: vec![TypeId::of::<A0>(), TypeId::of::<A1>(), TypeId::of::<A2>()],
            }
        }
    }

    pub enum NameDef {
        Port { is_putter: bool, type_id: TypeId },
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

#[derive(Debug)]
pub enum Term<I> {
    True,                         // returns bool
    False,                        // returns bool
    Not(Box<Self>),               // returns bool
    And(Vec<Self>),               // returns bool
    Or(Vec<Self>),                // returns bool
    IsEq(TypeId, Box<[Self; 2]>), // returns bool
    Named(I),                     // type of I
}

#[derive(Debug)]
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

#[derive(Debug)]
pub enum ProtoBuildError {
    UnavailableData { name: Name, rule_index: usize },
    InstructionHasSideEffects { name: Name, rule_index: usize },
    DuplicateNameDef { name: Name },
    MemoryNotInitialized { name: Name },
}

mod inner {
    use crate::outer::TypeInfo;
    use crate::*;
    use maplit::{hashmap, hashset};

    fn data_ptr_of(x: &Box<dyn PortDatum>) -> Ptr {
        let converted: &std::raw::TraitObject = unsafe { transmute(x) };
        converted.data
    }

    #[derive(Debug)]
    pub enum Space {
        PoPu(PutterSpace, MsgBox),
        PoGe(MsgBox),
        Memo(PutterSpace),
    }
    impl Space {
        fn get_putter_space(&self) -> Option<&PutterSpace> {
            match self {
                Space::PoPu(ps, _mb) => Some(ps),
                Space::PoGe(_mb) => None,
                Space::Memo(ps) => Some(ps),
            }
        }
    }
    #[derive(Debug)]
    pub struct MsgBox;

    pub fn build_proto(p: outer::Proto) -> Result<inner::Proto, ProtoBuildError> {
        use crate::ProtoBuildError::*;
        use outer::{MemDef, NameDef};

        let mut spaces = vec![];
        let mut name_mapping = BidirMap::<Name, LocId>::new();
        let mut unclaimed = hashmap! {};
        let mut allocator = Allocator::default();
        let info = p.info;

        for (name, def) in p.name_defs {
            let id = LocId(spaces.len());
            name_mapping.insert(name, id);
            let space = match def {
                NameDef::Port { is_putter, type_id } => {
                    unclaimed.insert(id, (is_putter, type_id));
                    let ps = PutterSpace::new(std::ptr::null_mut(), type_id);
                    Space::PoPu(ps, MsgBox)
                }
                NameDef::Mem(mem_def) => {
                    let (ptr, type_id) = match mem_def {
                        MemDef::Initialized(bx) => {
                            let q = (data_ptr_of(&bx), bx.my_type_id());
                            allocator.store(bx);
                            q
                        }
                        MemDef::Uninitialized(type_id) => (std::ptr::null_mut(), type_id),
                    };
                    Space::Memo(PutterSpace::new(ptr, type_id))
                }
                NameDef::Func(call_handle) => unimplemented!(),
            };
            spaces.push(space);
        }
        // temp vars
        // let mut temp_name_2_id = hashmap!{};
        // let mut available_resources = hashset!{};

        let rules = p
            .rules
            .iter()
            .map(|rule| {
                let ready_ports = hashset! {};
                let full_mem = hashset! {};
                let empty_mem = hashset! {};
                Ok(inner::Rule {
                    ready_ports,
                    full_mem,
                    empty_mem,
                    ins: vec![],
                    output: vec![],
                })
            })
            .collect::<Result<_, ProtoBuildError>>()?;

        let mem = BitSet::default();
        let ready = BitSet::default();
        Ok(Proto {
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
            },
        })
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

    #[derive(Debug)]
    pub struct Proto {
        cr: ProtoCr,
        r: ProtoR,
    }

    #[derive(Debug)]
    pub struct ProtoR {
        rules: Vec<Rule>,
        spaces: Vec<Space>,
        info: HashMap<TypeId, TypeInfo>,
        name_mapping: BidirMap<Name, LocId>,
    }

    type IsPutter = bool;
    #[derive(Debug)]
    pub struct ProtoCr {
        unclaimed: HashMap<LocId, (IsPutter, TypeId)>,
        ready: BitSet,
        mem: BitSet,
        allocator: Allocator,
    }

    type TraitData = *mut ();
    pub type TraitVtable = *mut ();

    #[derive(Debug, Default)]
    pub struct Allocator {
        allocated: HashMap<TraitVtable, Vec<TraitData>>,
        free: HashMap<TraitVtable, Vec<TraitData>>,
    }
    impl Allocator {
        pub fn store(&mut self, x: Box<dyn PortDatum>) {
            let to: std::raw::TraitObject = unsafe { transmute(x) };
            self.allocated
                .entry(to.vtable)
                .or_insert_with(Vec::new)
                .push(to.data);
        }
    }
    impl Drop for Allocator {
        fn drop(&mut self) {
            for (&vtable, data_vec) in self.allocated.iter() {
                for &data in data_vec.iter() {
                    let to = std::raw::TraitObject { data, vtable };
                    let to: Box<dyn PortDatum> = unsafe { transmute(to) };
                    drop(to)
                }
            }
        }
    }

    #[derive(Debug)]
    pub struct Rendesvous {
        countdown: AtomicUsize,
        moved: AtomicBool,
    }
    #[derive(Debug)]
    pub struct PutterSpace {
        ptr: AtomicPtr<()>,
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

    #[derive(Debug)]
    pub struct Rule {
        ready_ports: BitSet,
        full_mem: BitSet,
        empty_mem: BitSet,
        ins: Vec<Instruction<LocId, FuncId>>, // dummy
        output: Vec<(LocId, Vec<LocId>)>,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
    pub struct LocId(usize);
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
            Named(i) => r.spaces[i.0].get_putter_space().unwrap().ptr.load(SeqCst),
            // MUST BE BOOL
            True => bool_to_ptr(true),
            False => bool_to_ptr(false),
            Not(t) => bool_to_ptr(!eval_bool(t, r)),
            And(ts) => bool_to_ptr(ts.iter().all(|t| eval_bool(t, r))),
            Or(ts) => bool_to_ptr(ts.iter().any(|t| eval_bool(t, r))),
            IsEq(tid, terms) => bool_to_ptr(eval_bool(term, r)),
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
            Named(i) => ptr_to_bool(eval_ptr(term, r)),
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
                let to: &dyn PortDatum = unsafe {
                    transmute(TraitObject {
                        data: ptr0,
                        vtable: info.0,
                    })
                };
                to.my_eq(ptr0)
            }
        }
    }
}

pub trait PortDatum {
    // const IS_COPY: bool;
    // const TYPE_ID: TypeId;
    fn my_type_id(&self) -> TypeId;
    fn my_clone(&self, other: Ptr);
    fn my_eq(&self, other: Ptr) -> bool;
}

impl<T: 'static + Clone + PartialEq> PortDatum for T {
    fn my_type_id(&self) -> TypeId {
        TypeId::of::<T>()
    }
    fn my_clone(&self, other: Ptr) {
        let x: *mut Self = unsafe { transmute(other) };
        unsafe { x.write(self.clone()) }
    }
    fn my_eq(&self, other: Ptr) -> bool {
        let x: &Self = unsafe { transmute(other) };
        self == x
    }
}

use maplit::{hashmap, hashset};
use parking_lot::Mutex;
use std::any::TypeId;
use std::collections::HashSet;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::sync::Arc;

fn main() -> Result<(), ProtoBuildError> {
    use outer::*;
    use Instruction::*;
    use PortKind::*;
    use Term::*;


	#[derive(Clone, PartialEq)]
    struct MyType;
    impl Drop for MyType {
    	fn drop(&mut self) {
    		println!("droppy!");
    	}
    }

    let proto = Proto {
        info: hashmap! {
            TypeId::of::<u32>() => TypeInfo::of::<u32>(),
        },
        name_defs: hashmap! {
            "A" => NameDef::Port { is_putter:true, type_id: TypeId::of::<u32>() },
            "B" => NameDef::Port { is_putter:true, type_id: TypeId::of::<u32>() },
            "C" => NameDef::Port { is_putter:true, type_id: TypeId::of::<u32>() },
            "D" => NameDef::Mem(MemDef::Initialized(Box::new(MyType))),
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
    let built = build_proto(proto)?;
    println!("built: {:#?}", &built);
    Ok(())
}
