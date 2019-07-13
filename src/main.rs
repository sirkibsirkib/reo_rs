#![feature(raw)]
#![feature(box_patterns)]
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
    use crate::Instruction;
    use crate::Term;
    use std::any::Any;
    use std::any::TypeId;
    use std::collections::{HashMap, HashSet};
    use std::mem::transmute;
    use std::mem::ManuallyDrop;

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
        pub fn new_nonary<R: 'static>(func: Box<dyn Fn(*mut R)>) -> Self {
            CallHandle {
                func: unsafe { transmute(func) },
                ret: TypeId::of::<R>(),
                args: vec![],
            }
        }
        pub fn new_unary<R: 'static, A0: 'static>(func: Box<dyn Fn(*mut R, *const A0)>) -> Self {
            CallHandle {
                func: unsafe { transmute(func) },
                ret: TypeId::of::<R>(),
                args: vec![TypeId::of::<A0>()],
            }
        }
        pub fn new_binary<R: 'static, A0: 'static, A1: 'static>(
            func: Box<dyn Fn(*mut R, *const A0, *const A1)>,
        ) -> Self {
            CallHandle {
                func: unsafe { transmute(func) },
                ret: TypeId::of::<R>(),
                args: vec![TypeId::of::<A0>(), TypeId::of::<A1>()],
            }
        }
        pub fn new_ternary<R: 'static, A0: 'static, A1: 'static, A2: 'static>(
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
    UndefinedName { name: Name },
    InstructionHasSideEffects { name: Name, rule_index: usize },
    DuplicateNameDef { name: Name },
    MemoryNotInitialized { name: Name },
    TermNameIsNotPutter { name: Name },
    EqForDifferentTypes,
}

mod inner {
    use crate::outer::CallHandle;
    use crate::outer::RulePremise;
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

        // consume all name defs, creating spaces. retain call_handles to be treated later
        let call_handles: HashMap<Name, CallHandle> = p
            .name_defs
            .into_iter()
            .filter_map(|(name, def)| {
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
                    NameDef::Func(call_handle) => return Some((name, call_handle)),
                };
                spaces.push(space);
                None
            })
            .collect();
        // temp vars
        let mut temp_names = hashmap!{};
        // let mut available_resources = hashset!{};

        let rules = p
            .rules
            .into_iter()
            .map(|rule| {
                let RulePremise {
                    ready_ports,
                    full_mem,
                    empty_mem,
                } = rule.premise;
                let clos = |name| {
                    name_mapping
                        .get_by_first(&name)
                        .copied()
                        .ok_or(UndefinedName { name })
                };
                let ready_ports = ready_ports
                    .into_iter()
                    .map(clos)
                    .collect::<Result<_, ProtoBuildError>>()?;
                let full_mem = full_mem
                    .into_iter()
                    .map(clos)
                    .collect::<Result<_, ProtoBuildError>>()?;
                let empty_mem = empty_mem
                    .into_iter()
                    .map(clos)
                    .collect::<Result<_, ProtoBuildError>>()?;

                fn resolve_putter(
                	temp_names: &HashMap<Name, (LocId, TypeId)>,
                    name_mapping: &BidirMap<Name, LocId>,
                    name: Name,
                ) -> Result<LocId, ProtoBuildError> {
                    name_mapping
                        .get_by_first(&name)
                        .copied()
                        .ok_or(UndefinedName { name })
                }

                fn term_eval_tid(
                    spaces: &Vec<Space>,
                	temp_names: &HashMap<Name, (LocId, TypeId)>,
                    name_mapping: &BidirMap<Name, LocId>,
                    term: &Term<Name>,
                ) -> Result<TypeId, ProtoBuildError> {
                    use Term::*;
                    Ok(match term {
                        Named(name) => {
                            spaces[resolve_putter(temp_names, name_mapping, name)?.0]
                                .get_putter_space()
                                .ok_or(TermNameIsNotPutter { name })?
                                .type_id
                        }
                        _ => TypeId::of::<bool>(),
                    })
                }
                fn term_eval_loc_id(
                    spaces: &Vec<Space>,
                	temp_names: &HashMap<Name, (LocId, TypeId)>,
                    name_mapping: &BidirMap<Name, LocId>,
                    term: Term<Name>,
                ) -> Result<Term<LocId>, ProtoBuildError> {
                    use Term::*;
                    let clos = |fs: Vec<Term<Name>>| {
                        fs.into_iter()
                            .map(|t: Term<Name>| term_eval_loc_id(spaces, temp_names, name_mapping, t))
                            .collect::<Result<_, ProtoBuildError>>()
                    };
                    Ok(match term {
                        True => True,
                        False => False,
                        Not(f) => Not(Box::new(term_eval_loc_id(spaces, temp_names, name_mapping, *f)?)),
                        And(fs) => And(clos(fs)?),
                        Or(fs) => Or(clos(fs)?),
                        IsEq(tid, box [lhs, rhs]) => {
                            let [t0, t1] = [
                                term_eval_tid(spaces, temp_names, name_mapping, &lhs)?,
                                term_eval_tid(spaces, temp_names, name_mapping, &rhs)?,
                            ];
                            if t0 != t1 || t0 != tid {
                                return Err(EqForDifferentTypes);
                            }
                            IsEq(
                                tid,
                                Box::new([
                                    term_eval_loc_id(spaces, temp_names, name_mapping, lhs)?,
                                    term_eval_loc_id(spaces, temp_names, name_mapping, rhs)?,
                                ]),
                            )
                        }
                        Named(name) => Named(resolve_putter(temp_names, name_mapping, name)?),
                    })
                }

                let ins = rule.ins.into_iter().map(|i| {
                    use Instruction::*;
                    Ok(match i {
                        CreateFromFormula { dest, term } => {
                        	let dest_id = resolve_putter(&temp_names, &name_mapping, dest)?;
                        	let type_id = term_eval_tid(&spaces, &temp_names, &name_mapping, &term)?;
                        	temp_names.insert(dest, (dest_id, type_id));
                        	let term = term_eval_loc_id(&spaces, &temp_names, &name_mapping, term)?;
                        	CreateFromFormula { dest: dest_id, term }
                        }
                        CreateFromCall { dest, func, args } => {
                        	//todo
                        }
                        Check { term } => {
                            Check { term: term_eval_loc_id(&spaces, &temp_names, &name_mapping, term)? }
                        }
                    })
                }).collect::<Result<_, ProtoBuildError>>()?;

                Ok(inner::Rule {
                    ready_ports,
                    full_mem,
                    empty_mem,
                    ins,
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
        allocated: HashMap<TraitVtable, HashSet<TraitData>>,
        free: HashMap<TraitVtable, HashSet<TraitData>>,
    }
    impl Allocator {
        pub fn store(&mut self, x: Box<dyn PortDatum>) -> bool {
            let to: std::raw::TraitObject = unsafe { transmute(x) };
            !self
                .allocated
                .entry(to.vtable)
                .or_insert_with(HashSet::new)
                .insert(to.data)
        }
        pub fn remove(&mut self, to: TraitObject) -> bool {
            if let Some(set) = self.free.get_mut(&to.vtable) {
                set.remove(&to.data)
            } else {
                false
            }
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
            "E" => NameDef::Func(CallHandle::new_nonary(Box::new(|x: *mut u32| unsafe {
                x.write(7u32)
            }))),
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
