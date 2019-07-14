#![feature(raw)]
#![feature(box_patterns)]
// #![feature(specialization)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]

use bidir_map::BidirMap;
use core::sync::atomic::AtomicBool;
use debug_stub_derive::DebugStub;
use maplit::{hashmap, hashset};
use parking_lot::Mutex;
use std::alloc::Layout;
use std::any::Any;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::mem::transmute;
use std::mem::ManuallyDrop;
use std::raw::TraitObject;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;

mod building;
use building::*;

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


#[derive(DebugStub)]
pub struct CallHandle {
    #[debug_stub = "FuncTraitObject"]
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
        info: TypeInfo,
        dest: I,
        func: F,
        args: Vec<Term<I>>,
    },
    Check {
        term: Term<I>,
    },
    // TODO move data between memcells
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

#[derive(Debug)]
pub struct Proto {
    cr: Mutex<ProtoCr>,
    r: ProtoR,
}
impl Proto {
    pub(crate) fn ready_set_coordinate(&self, id: LocId) {
        let mut x = self.cr.lock();
        let success = x.ready.insert(id);
        assert!(success);
        x.coordinate(&self.r);
    }
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
    ref_counts: HashMap<TraitData, usize>,
}
impl ProtoCr {
    fn drop_memo(&mut self, r: &ProtoR, id: LocId) {
        let putter_space = r.spaces[id.0].get_putter_space().unwrap();
        let ptr = putter_space.ptr.swap(NULL, SeqCst);
        assert!(ptr != NULL);
        let ct = self.ref_counts.get_mut(&ptr).unwrap();
        if *ct == 1 {
            self.ref_counts.remove(&ptr);
            assert!(self.allocator.drop_inside(ptr, putter_space.type_info));
        } else {
            *ct -= 1;
        }
    }
    fn coordinate(&mut self, r: &ProtoR) {
        'outer: loop {
            'rules: for rule in r.rules.iter() {
                if !rule.ready_ports.is_subset(&self.ready)
                // || !rule.full_mem.is_subset(&self.mem)
                // || rule.empty_mem.is_disjoint(&self.mem)
                {
                    // failed guard
                    println!("FAILED G for {:?}", rule);
                    continue 'rules;
                }
                // TODO guards etc.
                println!("going to eval ins for rule {:?}", rule);
                for (i_id, i) in rule.ins.iter().enumerate() {
                    use Instruction::*;
                    match i {
                        CreateFromFormula { dest, term } => {
                            let dest_ptr = self.allocator.alloc_uninit(TypeInfo::of::<bool>());
                            // MUST BE BOOL. creation ensures it
                            unsafe {
                                let dest: *mut bool = transmute(dest_ptr);
                                *dest = eval_bool(term, r);
                            }
                            r.spaces[dest.0]
                                .get_putter_space()
                                .unwrap()
                                .ptr
                                .store(dest_ptr, SeqCst);
                            let was = self.ref_counts.insert(dest_ptr, 0);
                            assert!(was.is_none());
                        }
                        CreateFromCall {
                            info,
                            dest,
                            func,
                            args,
                        } => {
                            let to: TraitObject = func.func;
                            let dest_ptr = match args.len() {
                                0 => {
                                    let funcy: &dyn Fn(TraitData) = unsafe { transmute(to) };
                                    let dest_ptr = self.allocator.alloc_uninit(*info);
                                    funcy(dest_ptr);
                                    dest_ptr
                                }
                                // TODO
                                _ => unreachable!(),
                            };
                            println!("dest is {:?}", dest_ptr);
                            let old = r.spaces[dest.0]
                                .get_putter_space()
                                .unwrap()
                                .ptr
                                .swap(dest_ptr, SeqCst);
                            assert_eq!(old, NULL);
                            let was = self.ref_counts.insert(dest_ptr, 1);
                            assert!(was.is_none());
                        }
                        Check { term } => {
                            if !eval_bool(term, r) {
                                // ROLLBACK!
                                println!("ROLLBACK!");
                                for (i_id, i) in rule.ins[0..i_id].iter().enumerate() {
                                    println!("... rolling back {:?}", i);
                                    match i {
                                        CreateFromFormula { dest, .. } => self.drop_memo(r, *dest),
                                        CreateFromCall { dest, .. } => self.drop_memo(r, *dest),
                                        Check { .. } => {}
                                    }
                                }
                                println!("DID CreateFromCall");
                                continue 'rules;
                            }
                            println!("Passed check!");
                        }
                    }
                }
                // made it past the instructions! time to commit!
                // TODO
                continue 'outer; // reconsider all rules
            }
            // finished all rules
            return;
        }
    }
}

pub type TraitData = *mut ();
const NULL: TraitData = std::ptr::null_mut();

pub type TraitVtable = *mut ();

#[derive(Debug, Default)]
pub struct Allocator {
    allocated: HashMap<TypeInfo, HashSet<TraitData>>,
    free: HashMap<TypeInfo, HashSet<TraitData>>,
}
impl Allocator {
    pub fn store(&mut self, x: Box<dyn PortDatum>) -> bool {
        let (data, info) = unsafe { trait_obj_break(x) };
        self.allocated
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
                return data;
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
            }
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
    move_code: AtomicU8,
}
#[derive(Debug)]
pub struct PutterSpace {
    ptr: AtomicPtr<()>,
    type_info: TypeInfo,
    rendesvous: Rendesvous,
}
impl PutterSpace {
    fn new(ptr: TraitData, type_info: TypeInfo) -> Self {
        PutterSpace {
            ptr: AtomicPtr::new(ptr),
            type_info,
            rendesvous: Rendesvous {
                countdown: 0.into(),
                move_code: 0.into(),
            },
        }
    }
}

// putters by default retain their da
#[derive(Debug)]
pub struct Rule {
    ready_ports: BitSet,
    full_mem: BitSet,
    empty_mem: BitSet,
    ins: Vec<Instruction<LocId, Arc<CallHandle>>>, // dummy
    output: Vec<Movement>,
}

#[derive(Debug)]
pub struct Movement {
    putter: LocId,
    getters: Vec<LocId>,
    putter_retains: bool,
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

fn main() -> Result<(), (usize, ProtoBuildError)> {
    use Instruction::*;
    use Term::*;

    let proto = ProtoDef {
        name_defs: hashmap! {
            "A" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<u32>() },
            "B" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<u32>() },
            "C" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<u32>() },
            "foo" => NameDef::Func(CallHandle::new_nonary(Box::new(|x: *mut u32| unsafe {
                println!("HELLO YOU ARE CALLING :3");
                x.write(7u32)
            }))),
        },
        rules: vec![RuleDef {
            premise: RulePremise {
                ready_ports: hashset! {"B"},
                full_mem: hashset! {},
                empty_mem: hashset! {},
            },
            ins: vec![
                Instruction::Check { term: Term::True },
                Instruction::CreateFromCall {
                    info: TypeInfo::of::<u32>(),
                    dest: "D",
                    func: "foo",
                    args: vec![],
                },
            ],
            output: hashmap! {
                "D" => (false, hashset!{"B"})
            },
        }],
    };
    let built = build_proto(proto)?;

    let b = built.r.name_mapping.get_by_first(&"B").unwrap();
    built.ready_set_coordinate(*b);

    // println!("built: {:#?}", &built);
    Ok(())
}
