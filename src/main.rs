#![feature(raw)]
#![feature(box_patterns)]
// #![feature(specialization)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]

use std::alloc::Layout;
use bidir_map::BidirMap;
use core::sync::atomic::AtomicBool;
use std::any::Any;
use std::collections::HashMap;
use std::mem::transmute;
use std::mem::ManuallyDrop;
use std::raw::TraitObject;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;

mod tests;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct TypeInfo(pub(crate) TraitVtable);
impl TypeInfo {
    pub fn of<T: PortDatum>() -> Self {
        // fabricate the data itself
        let bx: Box<T> = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        // have the compiler insert the correct vtable, using bogus data
        let dy_bx: Box<dyn PortDatum> = bx;
        // change compiler's view of the object
        let to: TraitObject = unsafe { transmute(dy_bx) };
        // return the legitimate vtable
        Self(to.vtable)
    }
    pub fn get_layout(self) -> Layout {
        let bogus = self.0;
        let to = unsafe { trait_obj_build(bogus, self) };
        let layout = to.my_layout();
        std::mem::forget(to);
        layout
    }
}

#[inline]
// not really unsafe. but leaks memory if not paired with a build
unsafe fn trait_obj_break(x: Box<dyn PortDatum>) -> (TraitData, TypeInfo) {
    let to: TraitObject = transmute(x);
    (to.data, TypeInfo(to.vtable))
}

#[inline]
unsafe fn trait_obj_build(data: TraitData, info: TypeInfo) -> Box<dyn PortDatum> {
    let x = TraitObject {
        data,
        vtable: info.0,
    };
    transmute(x)
}
#[inline]
unsafe fn trait_obj_read(x: &Box<dyn PortDatum>) -> (TraitData, TypeInfo) {
    let to: &TraitObject = transmute(x);
    (to.data, TypeInfo(to.vtable))
}

type FuncId = usize;

pub enum MemDef {
    Initialized(Box<dyn PortDatum>),
    Uninitialized(TypeInfo),
}

pub struct CallHandle {
    func: TraitObject,
    ret: TypeInfo,
    args: Vec<TypeInfo>,
}
impl CallHandle {
    pub fn new_nonary<R: PortDatum>(func: Box<dyn Fn(*mut R)>) -> Self {
        CallHandle {
            func: unsafe { transmute(func) },
            ret: TypeInfo::of::<R>(),
            args: vec![],
        }
    }
    pub fn new_unary<R: PortDatum, A0: PortDatum>(func: Box<dyn Fn(*mut R, *const A0)>) -> Self {
        CallHandle {
            func: unsafe { transmute(func) },
            ret: TypeInfo::of::<R>(),
            args: vec![TypeInfo::of::<A0>()],
        }
    }
    pub fn new_binary<R: PortDatum, A0: PortDatum, A1: PortDatum>(
        func: Box<dyn Fn(*mut R, *const A0, *const A1)>,
    ) -> Self {
        CallHandle {
            func: unsafe { transmute(func) },
            ret: TypeInfo::of::<R>(),
            args: vec![TypeInfo::of::<A0>(), TypeInfo::of::<A1>()],
        }
    }
    pub fn new_ternary<R: PortDatum, A0: PortDatum, A1: PortDatum, A2: PortDatum>(
        func: Box<dyn Fn(*mut R, *const A0, *const A1, *const A2)>,
    ) -> Self {
        CallHandle {
            func: unsafe { transmute(func) },
            ret: TypeInfo::of::<R>(),
            args: vec![
                TypeInfo::of::<A0>(),
                TypeInfo::of::<A1>(),
                TypeInfo::of::<A2>(),
            ],
        }
    }
}

pub enum NameDef {
    Port { is_putter: bool, type_id: TypeInfo },
    Mem(MemDef),
    Func(CallHandle),
}

pub struct ProtoDef {
    pub name_defs: HashMap<Name, NameDef>,
    pub rules: Vec<RuleDef>,
}

pub struct RulePremise {
    pub ready_ports: HashSet<Name>,
    pub full_mem: HashSet<Name>,
    pub empty_mem: HashSet<Name>,
}
pub struct RuleDef {
    pub premise: RulePremise,
    pub ins: Vec<Instruction<Name, Name>>,
    pub output: HashMap<Name, HashSet<Name>>,
}
pub type Name = &'static str;

#[derive(Debug)]
pub enum Term<I> {
    True,                           // returns bool
    False,                          // returns bool
    Not(Box<Self>),                 // returns bool
    And(Vec<Self>),                 // returns bool
    Or(Vec<Self>),                  // returns bool
    IsEq(TypeInfo, Box<[Self; 2]>), // returns bool
    Named(I),                       // type of I
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

pub fn build_proto(p: ProtoDef) -> Result<Proto, ProtoBuildError> {
    use crate::ProtoBuildError::*;

    let mut spaces = vec![];
    let mut name_mapping = BidirMap::<Name, LocId>::new();
    let mut unclaimed = hashmap! {};
    let mut allocator = Allocator::default();

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
                    let (ptr, info) = match mem_def {
                        MemDef::Initialized(bx) => unsafe {
                            let (data, info) = trait_obj_read(&bx);
                            allocator.store(bx);
                            (data, info)
                        },
                        MemDef::Uninitialized(info) => (std::ptr::null_mut(), info),
                    };
                    // putter space gets a copy too, not owned
                    Space::Memo(PutterSpace::new(ptr, info))
                }
                NameDef::Func(call_handle) => return Some((name, call_handle)),
            };
            spaces.push(space);
            None
        })
        .collect();
    // temp vars
    let mut temp_names = hashmap! {};
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
                temp_names: &HashMap<Name, (LocId, TypeInfo)>,
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
                temp_names: &HashMap<Name, (LocId, TypeInfo)>,
                name_mapping: &BidirMap<Name, LocId>,
                term: &Term<Name>,
            ) -> Result<TypeInfo, ProtoBuildError> {
                use Term::*;
                Ok(match term {
                    Named(name) => {
                        spaces[resolve_putter(temp_names, name_mapping, name)?.0]
                            .get_putter_space()
                            .ok_or(TermNameIsNotPutter { name })?
                            .type_id
                    }
                    _ => TypeInfo::of::<bool>(),
                })
            }
            fn term_eval_loc_id(
                spaces: &Vec<Space>,
                temp_names: &HashMap<Name, (LocId, TypeInfo)>,
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
                    Not(f) => Not(Box::new(term_eval_loc_id(
                        spaces,
                        temp_names,
                        name_mapping,
                        *f,
                    )?)),
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

            let ins = rule
                .ins
                .into_iter()
                .map(|i| {
                    use Instruction::*;
                    Ok(match i {
                        CreateFromFormula { dest, term } => {
                            let dest_id = resolve_putter(&temp_names, &name_mapping, dest)?;
                            let type_id =
                                term_eval_tid(&spaces, &temp_names, &name_mapping, &term)?;
                            temp_names.insert(dest, (dest_id, type_id));
                            let term = term_eval_loc_id(&spaces, &temp_names, &name_mapping, term)?;
                            CreateFromFormula {
                                dest: dest_id,
                                term,
                            }
                        }
                        CreateFromCall { dest, func, args } => {
                            //todo
                            unimplemented!()
                        }
                        Check { term } => Check {
                            term: term_eval_loc_id(&spaces, &temp_names, &name_mapping, term)?,
                        },
                    })
                })
                .collect::<Result<_, ProtoBuildError>>()?;

            Ok(Rule {
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

#[derive(Debug)]
pub struct Proto {
    cr: ProtoCr,
    r: ProtoR,
}

#[derive(Debug)]
pub struct ProtoR {
    rules: Vec<Rule>,
    spaces: Vec<Space>,
    name_mapping: BidirMap<Name, LocId>,
}

type IsPutter = bool;
#[derive(Debug)]
pub struct ProtoCr {
    unclaimed: HashMap<LocId, (IsPutter, TypeInfo)>,
    ready: BitSet,
    mem: BitSet,
    allocator: Allocator,
}

pub type TraitData = *mut ();
pub type TraitVtable = *mut ();

#[derive(Debug, Default)]
pub struct Allocator {
    allocated: HashMap<TypeInfo, HashSet<TraitData>>,
    free: HashMap<TypeInfo, HashSet<TraitData>>,
}
impl Allocator {
    pub fn store(&mut self, x: Box<dyn PortDatum>) -> bool {
        let (data, info) = unsafe { trait_obj_break(x) };
        self
            .allocated
            .entry(info)
            .or_insert_with(HashSet::new)
            .insert(data)
    }
    pub fn alloc_uninit(&mut self, type_info: TypeInfo) -> TraitData {
        if let Some(set) = self.free.get_mut(&type_info) {
            // re-using freed
            if let Some(data) = set.iter().copied().next() {
                set.remove(&data);
                let success = self
                    .allocated
                    .entry(type_info)
                    .or_insert_with(HashSet::new)
                    .insert(data);
                assert!(success);
                return data
            }
        }
        // crate a new allocation
        unsafe {
            let layout = type_info.get_layout();
            let data = transmute(std::alloc::alloc(layout));
            let success = self.store(trait_obj_build(data, type_info));
            assert!(success);
            data        
        }
    }
    pub fn drop_inside(&mut self, data: TraitData, type_info: TypeInfo) -> bool {
        if let Some(set) = self.allocated.get_mut(&type_info) {
            if set.remove(&data) {
                unsafe {
                    let mut bx = trait_obj_build(data, type_info);
                    bx.drop_in_place();
                    trait_obj_break(bx);
                }
                let success = self
                    .free
                    .entry(type_info)
                    .or_insert_with(HashSet::new)
                    .insert(data);
                return success;
            } else {
                println!("NOT FOR THIS DATUM");
            }
        } else {
            println!("NOT FOR THIS INFO");
        }
        false
    }
    pub fn remove(&mut self, data: TraitData, type_info: TypeInfo) -> bool {
        if let Some(set) = self.free.get_mut(&type_info) {
            set.remove(&data)
        } else {
            false
        }
    }
}
impl Drop for Allocator {
    fn drop(&mut self) {
        // drop all owned values
        for (&vtable, data_vec) in self.allocated.iter() {
            for &data in data_vec.iter() {
                drop(unsafe { trait_obj_build(data, vtable) })
            }
        }
        // drop all empty boxes
        let empty_box_vtable = TypeInfo::of::<Box<()>>();
        for (&vtable, data_vec) in self.free.iter() {
            for &data in data_vec.iter() {
                drop(unsafe { trait_obj_build(data, empty_box_vtable) });
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
    type_id: TypeInfo,
    rendesvous: Rendesvous,
}
impl PutterSpace {
    fn new(ptr: TraitData, type_id: TypeInfo) -> Self {
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
fn bool_to_ptr(x: bool) -> TraitData {
    unsafe {
        transmute(if x {
            &mut true as *mut bool
        } else {
            &mut false as *mut bool
        })
    }
}

fn eval_ptr(term: &Term<LocId>, r: &ProtoR) -> TraitData {
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
fn ptr_to_bool(x: TraitData) -> bool {
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
        IsEq(info, terms) => {
            let ptr0 = eval_ptr(&terms[0], r);
            let ptr1 = eval_ptr(&terms[1], r);
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

pub trait PortDatum {
    fn my_clone(&self, other: TraitData);
    fn my_eq(&self, other: TraitData) -> bool;
    unsafe fn drop_in_place(&mut self);
    fn my_layout(&self) -> Layout;
}

impl<T: 'static + Clone + PartialEq> PortDatum for T {
    fn my_clone(&self, other: TraitData) {
        let x: *mut Self = unsafe { transmute(other) };
        unsafe { x.write(self.clone()) }
    }
    fn my_eq(&self, other: TraitData) -> bool {
        let x: &Self = unsafe { transmute(other) };
        self == x
    }
    unsafe fn drop_in_place(&mut self) {
        std::intrinsics::drop_in_place(self)
    }
    fn my_layout(&self) -> Layout {
        Layout::new::<T>()
    }
}

use maplit::{hashmap, hashset};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::sync::Arc;

fn main() -> Result<(), ProtoBuildError> {
    use Instruction::*;
    use Term::*;

    #[derive(Clone, PartialEq)]
    struct MyType;
    impl Drop for MyType {
        fn drop(&mut self) {
            println!("droppy!");
        }
    }

    let proto = ProtoDef {
        name_defs: hashmap! {
            "A" => NameDef::Port { is_putter:true, type_id: TypeInfo::of::<u32>() },
            "B" => NameDef::Port { is_putter:true, type_id: TypeInfo::of::<u32>() },
            "C" => NameDef::Port { is_putter:true, type_id: TypeInfo::of::<u32>() },
            "D" => NameDef::Mem(MemDef::Initialized(Box::new(MyType))),
            "E" => NameDef::Func(CallHandle::new_nonary(Box::new(|x: *mut u32| unsafe {
                x.write(7u32)
            }))),
        },
        rules: vec![
            RuleDef {
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
            RuleDef {
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
