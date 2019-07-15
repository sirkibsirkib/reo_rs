#![feature(raw)]
#![feature(box_patterns)]
#![feature(specialization)]
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
use std::mem::MaybeUninit;
use std::raw::TraitObject;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;
use std_semaphore::Semaphore;

mod building;
use building::*;

mod tests;

unsafe impl Send for TypeInfo {}
unsafe impl Sync for TypeInfo {}
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
        let r = to.my_layout();
        std::mem::forget(to);
        r
    }
    pub fn is_copy(self) -> bool {
        let bogus = self.0;
        let to = unsafe { trait_obj_build(bogus, self) };
        let r = to.is_copy();
        std::mem::forget(to);
        r
    }
    pub unsafe fn copy(self, src: TraitData, dest: TraitData) {
        let to = trait_obj_build(src, self);
        let layout = to.my_layout();
        let [src_u8, dest_u8]: [*mut u8; 2] = transmute([src, dest]);
        println!("COPYING with layout {:?}", layout);
        std::ptr::copy(src_u8, dest_u8, layout.size());
        std::mem::forget(to);
    }
    pub unsafe fn clone(self, src: TraitData, dest: TraitData) {
        let to = trait_obj_build(src, self);
        let r = to.my_clone(dest);
        std::mem::forget(to);
        r
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

unsafe impl Send for CallHandle {}
unsafe impl Sync for CallHandle {}
#[allow(bare_trait_objects)] // DebugStub can't parse the new dyn syntax :(
#[derive(DebugStub, Clone)]
pub struct CallHandle {
    #[debug_stub = "FuncTraitObject"]
    func: Arc<Fn()>,
    ret: TypeInfo,
    args: Vec<TypeInfo>,
}
impl CallHandle {
    pub fn new_nonary<R: PortDatum>(func: Arc<dyn Fn(*mut R) + Sync>) -> Self {
        CallHandle {
            func: unsafe { transmute(func) },
            ret: TypeInfo::of::<R>(),
            args: vec![],
        }
    }
    pub fn new_unary<R: PortDatum, A0: PortDatum>(
        func: Arc<dyn Fn(*mut R, *const A0) + Sync>,
    ) -> Self {
        CallHandle {
            func: unsafe { transmute(func) },
            ret: TypeInfo::of::<R>(),
            args: vec![TypeInfo::of::<A0>()],
        }
    }
    pub fn new_binary<R: PortDatum, A0: PortDatum, A1: PortDatum>(
        func: Arc<dyn Fn(*mut R, *const A0, *const A1) + Sync>,
    ) -> Self {
        CallHandle {
            func: unsafe { transmute(func) },
            ret: TypeInfo::of::<R>(),
            args: vec![TypeInfo::of::<A0>(), TypeInfo::of::<A1>()],
        }
    }
    pub fn new_ternary<R: PortDatum, A0: PortDatum, A1: PortDatum, A2: PortDatum>(
        func: Arc<dyn Fn(*mut R, *const A0, *const A1, *const A2) + Sync>,
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
    MemMove {
        src: I,
        dest: I,
    }, // TODO move data between memcells
}
#[derive(Debug)]
pub enum Space {
    PoPu { ps: PutterSpace, mb: MsgBox },
    PoGe { mb: MsgBox },
    Memo { ps: PutterSpace },
}
impl Space {
    fn get_putter_space(&self) -> Option<&PutterSpace> {
        match self {
            Space::PoPu { ps, .. } => Some(ps),
            Space::PoGe { .. } => None,
            Space::Memo { ps } => Some(ps),
        }
    }
    fn get_msg_box(&self) -> Option<&MsgBox> {
        match self {
            Space::PoPu { mb, .. } => Some(mb),
            Space::PoGe { mb } => Some(mb),
            Space::Memo { .. } => None,
        }
    }
}
#[derive(Debug)]
pub struct MsgBox {
    s: crossbeam_channel::Sender<usize>,
    r: crossbeam_channel::Receiver<usize>,
}
impl Default for MsgBox {
    fn default() -> Self {
        let (s, r) = crossbeam_channel::bounded(1);
        Self { s, r }
    }
}
impl MsgBox {
    const MOVED_MSG: usize = 0xadded;
    const UNMOVED_MSG: usize = 0xdeaf;
    pub fn send(&self, msg: usize) {
        println!(">>> sending {:X}", msg);
        self.s.try_send(msg).unwrap();
    }
    pub fn recv(&self) -> usize {
        let msg = self.r.recv().unwrap();
        println!("<<< recved {:X}", msg);
        msg
    }
}

#[derive(Debug)]
pub struct Proto {
    cr: Mutex<ProtoCr>,
    r: ProtoR,
}

impl Eq for ProtoHandle {}
#[derive(Debug, Clone)]
pub struct ProtoHandle(Arc<Proto>);
impl PartialEq for ProtoHandle {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

#[derive(Debug)]
pub enum ClaimError {
    WrongPortDirection,
    TypeMismatch(TypeInfo),
    UnknownName,
    AlreadyClaimed,
}

#[derive(Debug)]
struct PortCommon {
    id: LocId,
    type_info: TypeInfo,
    p: ProtoHandle,
}
impl PortCommon {
    fn claim(
        name: Name,
        want_putter: bool,
        want_type_info: TypeInfo,
        p: &ProtoHandle,
    ) -> Result<Self, ClaimError> {
        use ClaimError::*;
        if let Some(id) = p.0.r.name_mapping.get_by_first(&name) {
            let (is_putter, type_info) = *p.0.r.port_info.get(id).unwrap();
            if want_putter != is_putter {
                return Err(WrongPortDirection);
            } else if want_type_info != type_info {
                return Err(TypeMismatch(type_info));
            }
            let mut x = p.0.cr.lock();
            if x.unclaimed.remove(id) {
                let q = Ok(Self {
                    id: *id,
                    type_info,
                    p: p.clone(),
                });
                println!("{:?}", q);
                q
            } else {
                Err(AlreadyClaimed)
            }
        } else {
            Err(ClaimError::UnknownName)
        }
    }
}

struct Putter<T: PortDatum>(PortCommon, PhantomData<T>);
impl<T: PortDatum> Putter<T> {
    fn claim(p: &ProtoHandle, name: Name) -> Result<Self, ClaimError> {
        Ok(Self(
            PortCommon::claim(name, true, TypeInfo::of::<T>(), p)?,
            Default::default(),
        ))
    }

    pub fn put(&mut self, mut datum: T) -> Option<T> {
        let ptr: TraitData = unsafe { transmute(&mut datum) };
        let space = &self.0.p.0.r.spaces[self.0.id.0];
        if let Space::PoPu { ps, mb } = space {
            assert_eq!(NULL, ps.ptr.swap(ptr, SeqCst));
            {
                let mut x = self.0.p.0.cr.lock();
                assert!(x.ready.insert(self.0.id));
                x.coordinate(&self.0.p.0.r);
            }
            println!("waitinig,...");
            let msg = mb.recv();
            println!("...got!");
            println!("MSG 0x{:X}", msg);
            ps.ptr.swap(NULL, SeqCst);
            match msg {
                MsgBox::MOVED_MSG => {
                    std::mem::forget(datum);
                    None
                }
                MsgBox::UNMOVED_MSG => Some(datum),
                _ => panic!("BAD MSG"),
            }
        } else {
            panic!("WRONG SPACE")
        }
    }
}
struct Getter<T: PubPortDatum>(PortCommon, PhantomData<T>);
impl<T: PubPortDatum> Getter<T> {
    fn claim(p: &ProtoHandle, name: Name) -> Result<Self, ClaimError> {
        Ok(Self(
            PortCommon::claim(name, false, TypeInfo::of::<T>(), p)?,
            Default::default(),
        ))
    }

    fn get_data<F: FnOnce(bool)>(
        ps: &PutterSpace,
        maybe_dest: Option<&mut MaybeUninit<T>>,
        finalize: F,
    ) {
        // Do NOT NULLIFY SRC PTR. FINALIZE WILL DO THAT
        println!("GET DATA");
        let ptr: TraitData = ps.ptr.load(SeqCst);
        assert!(ptr != NULL);
        println!("GETTER GOT PTR {:p}", ptr);
        let do_move = move |dest: &mut MaybeUninit<T>| unsafe {
            let s: *const T = transmute(ptr);
            dest.as_mut_ptr().write(s.read());
        };
        let do_clone = move |dest: &mut MaybeUninit<T>| unsafe {
            let s: &T = transmute(ptr);
            dest.as_mut_ptr().write(s.my_clone2());
        };

        if T::IS_COPY {
            if let Some(dest) = maybe_dest {
                do_move(dest);
                ps.rendesvous.move_flags.type_is_copy_i_moved();
            }
            let was = ps.rendesvous.countdown.fetch_sub(1, SeqCst);
            if was == 1 {
                    println!("I LAST (B)");
                let somebody_moved = ps.rendesvous.move_flags.did_someone_move();
                finalize(somebody_moved);
            }
        } else {
            if let Some(dest) = maybe_dest {
                let won = !ps.rendesvous.move_flags.ask_for_move_permission();
                if won {
                    println!("I WIN (B)");
                    let was = ps.rendesvous.countdown.fetch_sub(1, SeqCst);
                    if was == 1 {
                        do_move(dest);
                    } else {
                        ps.rendesvous.mover_sema.acquire();
                    }
                    finalize(true);
                } else {
                    // lose
                    println!("I LOSE (B)");
                    do_clone(dest);
                    let was = ps.rendesvous.countdown.fetch_sub(1, SeqCst);
                    if was == 1 {
                        // all clones are done
                        ps.rendesvous.mover_sema.release();
                    } else {
                        // do nothing
                    }
                }
            } else {
                let was = ps.rendesvous.countdown.fetch_sub(1, SeqCst);
                if was == 1 {
                    println!("I WIN (C)");
                    // all clones done
                    let nobody_else_won = !ps.rendesvous.move_flags.ask_for_move_permission();
                    if nobody_else_won {
                        finalize(false);
                    } else {
                        ps.rendesvous.mover_sema.release();
                    }
                }
            }
        }
    }

    pub fn get(&mut self) -> T {
        let space = &self.0.p.0.r.spaces[self.0.id.0];
        let mut ret = MaybeUninit::uninit();
        if let Space::PoGe { mb } = space {
            {
                let mut x = self.0.p.0.cr.lock();
                assert!(x.ready.insert(self.0.id));
                x.coordinate(&self.0.p.0.r);
            }
            let putter_id = LocId(mb.recv());
            match &self.0.p.0.r.spaces[putter_id.0] {
                Space::PoPu { ps, mb } => Self::get_data(ps, Some(&mut ret), move |was_moved| {
                    // finalization function
                    if was_moved {
                        assert!(NULL != ps.ptr.swap(NULL, SeqCst));
                        mb.send(MsgBox::MOVED_MSG)
                    } else {
                        mb.send(MsgBox::UNMOVED_MSG)
                    };
                }),
                Space::Memo { ps } => Self::get_data(ps, Some(&mut ret), |was_moved| {
                    // finalization function
                    println!("was moved? {:?}", was_moved);
                    self.0
                        .p
                        .0
                        .cr
                        .lock()
                        .finalize_memo(&self.0.p.0.r, putter_id, was_moved);
                }),
                Space::PoGe { .. } => panic!("CANNOT"),
            };
        }
        unsafe { ret.assume_init() }
    }
}

#[derive(Debug)]
pub struct ProtoR {
    rules: Vec<Rule>,
    spaces: Vec<Space>,
    name_mapping: BidirMap<Name, LocId>,
    port_info: HashMap<LocId, (IsPutter, TypeInfo)>,
}
impl ProtoR {
    pub fn sanity_check(&self) {
        struct Cap {
            put: bool,
            msg: bool,
            mem: bool,
            ty: TypeInfo,
        };
        let capabilities: Vec<Cap> = self
            .spaces
            .iter()
            .enumerate()
            .map(|(id, x)| match x {
                Space::PoPu { ps, .. } => Cap {
                    put: true,
                    msg: true,
                    mem: false,
                    ty: ps.type_info,
                },
                Space::PoGe { .. } => Cap {
                    put: false,
                    msg: true,
                    mem: false,
                    ty: self.port_info.get(&LocId(id)).unwrap().1,
                },
                Space::Memo { ps } => Cap {
                    put: true,
                    msg: false,
                    mem: true,
                    ty: ps.type_info,
                },
            })
            .collect();
        for (k, (putter, tinfo)) in self.port_info.iter() {
            let cap = &capabilities[k.0];
            assert!(!cap.mem);
            assert_eq!(cap.put, *putter);
            assert_eq!(cap.ty, *tinfo);
        }
        for rule in self.rules.iter() {
            let mut known_filled = hashmap! {};
            for x in rule.bit_guard.ready.iter().copied() {
                let cap = &capabilities[x.0];
                if cap.mem {
                    // implies put
                    let f = rule.bit_guard.full_mem.contains(&x);
                    let e = rule.bit_guard.empty_mem.contains(&x);
                    assert!(!(f && e));
                    if f {
                        known_filled.insert(x, true);
                    }
                    if e {
                        known_filled.insert(x, false);
                    }
                } else {
                    known_filled.insert(x, cap.put);
                }
            }
            fn check_ret_type(
                capabilities: &Vec<Cap>,
                known_filled: &HashMap<LocId, bool>,
                term: &Term<LocId>,
            ) -> TypeInfo {
                use Term::*;
                let tbool = TypeInfo::of::<bool>();
                match term {
                    Named(i) => {
                        let cap = &capabilities[i.0];
                        assert_eq!(known_filled[i], true);
                        cap.ty
                    }
                    // MUST BE BOOL
                    True | False => TypeInfo::of::<bool>(),
                    Not(t) => {
                        assert_eq!(check_ret_type(capabilities, known_filled, t), tbool);
                        tbool
                    }
                    And(ts) | Or(ts) => {
                        for t in ts.iter() {
                            assert_eq!(check_ret_type(capabilities, known_filled, t), tbool);
                        }
                        tbool
                    }
                    IsEq(tid, terms) => {
                        assert_eq!(check_ret_type(capabilities, known_filled, &terms[0]), *tid);
                        assert_eq!(check_ret_type(capabilities, known_filled, &terms[1]), *tid);
                        tbool
                    }
                }
            }
            for i in rule.ins.iter() {
                match i {
                    Instruction::Check { term } => assert_eq!(
                        TypeInfo::of::<bool>(),
                        check_ret_type(&capabilities, &known_filled, term)
                    ),
                    Instruction::CreateFromCall {
                        info,
                        dest,
                        func,
                        args,
                    } => {
                        let cap = &capabilities[dest.0];
                        assert_eq!(*info, cap.ty);
                        assert_eq!(func.args.len(), args.len());
                        for (&t0, term) in func.args.iter().zip(args.iter()) {
                            let t1 = check_ret_type(&capabilities, &known_filled, term);
                            assert_eq!(t0, t1);
                        }
                    }
                    Instruction::CreateFromFormula { dest, term } => {
                        let cap = &capabilities[dest.0];
                        assert_eq!(cap.ty, check_ret_type(&capabilities, &known_filled, term))
                    }
                    Instruction::MemMove { src, dest } => {
                        assert_eq!(known_filled.get(src), Some(&true));
                        assert_eq!(known_filled.get(dest), Some(&false));
                        known_filled.insert(*src, false);
                        known_filled.insert(*dest, true);
                    }
                }
            }
            let mut busy_doing = hashmap! {}; // => true for put, => false for get
            for movement in rule.output.iter() {
                let p = movement.putter;
                assert_eq!(known_filled.get(&p), Some(&true));
                let cap = &capabilities[p.0];
                assert!(busy_doing.insert(p, true).is_none());

                assert_eq!(
                    cap.mem && !movement.putter_retains,
                    rule.bit_assign.empty_mem.contains(&p)
                );
                assert_eq!(
                    cap.mem && !movement.putter_retains,
                    rule.bit_assign.empty_mem.contains(&p)
                );
                for g in movement.me_ge.iter().copied() {
                    let gcap = &capabilities[g.0];
                    assert!(gcap.mem);
                    assert_eq!(cap.ty, gcap.ty);
                    assert_eq!(known_filled.get(&g), Some(&false));
                    assert!(rule.bit_assign.full_mem.contains(&g));
                    assert!(busy_doing.insert(g, false).is_none());
                }
                for g in movement.po_ge.iter().copied() {
                    let gcap = &capabilities[g.0];
                    assert!(!gcap.mem);
                    assert_eq!(cap.ty, gcap.ty);
                    assert_eq!(known_filled.get(&g), Some(&false));
                    assert!(!rule.bit_assign.full_mem.contains(&g));
                    assert!(busy_doing.insert(g, false).is_none());
                }
            }
            // make sure every READY-requested location is doing something
            for p in rule.bit_guard.ready.iter().copied() {
                assert!(busy_doing.contains_key(&p));
            }
            // todo check NON putters in assignment set
            for p in rule
                .bit_assign
                .empty_mem
                .iter()
                .chain(rule.bit_assign.full_mem.iter())
                .copied()
            {
                assert!(busy_doing.contains_key(&p));
            }
        }
    }
}

type IsPutter = bool;
#[derive(Debug)]
pub struct ProtoCr {
    unclaimed: HashSet<LocId>,
    ready: BitSet,
    mem: BitSet, // presence means FULL
    allocator: Allocator,
    ref_counts: HashMap<usize, usize>,
}
impl ProtoCr {
    fn finalize_memo(&mut self, r: &ProtoR, this_mem_id: LocId, was_moved: bool) {
        let putter_space = r.spaces[this_mem_id.0].get_putter_space().unwrap();
        let ptr = putter_space.ptr.swap(NULL, SeqCst);
        let ref_count = self.ref_counts.get_mut(&(ptr as usize)).unwrap();
        println!("FINALIZING SO {:?} IS READY", this_mem_id);
        assert!(*ref_count > 0);
        *ref_count -= 1;
        if *ref_count == 0 {
            self.ref_counts.remove(&(ptr as usize));
            if !was_moved {
                assert!(self.allocator.drop_inside(ptr, putter_space.type_info));
            } else {
                assert!(self.allocator.forget_inside(ptr, putter_space.type_info));
            }
        } else {
            assert!(!was_moved);
        }
        self.ready.insert(this_mem_id);
        self.coordinate(r);
    }
    fn coordinate(&mut self, r: &ProtoR) {
        println!("COORDINATE START. READY={:?} MEM={:?}", &self.ready, &self.mem);
        'outer: loop {
            'rules: for rule in r.rules.iter() {
                let g1 = rule.bit_guard.ready.is_subset(&self.ready);
                let g2 = rule.bit_guard.full_mem.is_subset(&self.mem);
                let g3 = rule.bit_guard.empty_mem.is_disjoint(&self.mem);
                if !(g1 && g2 && g3) {
                    // failed guard
                    println!("FAILED G for {:?}. ({}, {}, {})", rule, g1, g2, g3);
                    continue 'rules;
                }
                println!("SUCCESS");
                // println!("going to eval ins for rule {:?}", rule);
                for (i_id, i) in rule.ins.iter().enumerate() {
                    use Instruction::*;
                    match i {
                        MemMove { src, dest } => unimplemented!(),
                        CreateFromFormula { dest, term } => {
                            // MUST BE BOOL. creation ensures it
                            let dest_ptr = unsafe {
                                let dest_ptr = self.allocator.alloc_uninit(TypeInfo::of::<bool>());
                                let dest: *mut bool = transmute(dest_ptr);
                                *dest = eval_bool(term, r);
                                dest_ptr
                            };
                            r.spaces[dest.0]
                                .get_putter_space()
                                .unwrap()
                                .ptr
                                .store(dest_ptr, SeqCst);
                            let was = self.ref_counts.insert(dest_ptr as usize, 0);
                            assert!(was.is_none());
                        }
                        CreateFromCall {
                            info,
                            dest,
                            func,
                            args,
                        } => {
                            let to: &Arc<dyn Fn()> = &func.func;
                            let to: &TraitObject = unsafe { transmute(to) };
                            let to: TraitObject = *to;
                            let dest_ptr = match args.len() {
                                0 => {
                                    let funcy: &dyn Fn(TraitData) = unsafe { transmute(to) };
                                    unsafe {
                                        let dest_ptr = self.allocator.alloc_uninit(*info);
                                        funcy(dest_ptr);
                                        dest_ptr
                                    }
                                }
                                // TODO
                                _ => unreachable!(),
                            };
                            // println!("dest is {:?}", dest_ptr);
                            let old = r.spaces[dest.0]
                                .get_putter_space()
                                .unwrap()
                                .ptr
                                .swap(dest_ptr, SeqCst);
                            assert_eq!(old, NULL);
                            let was = self.ref_counts.insert(dest_ptr as usize, 1);
                            assert!(was.is_none());
                        }
                        Check { term } => {
                            if !eval_bool(term, r) {
                                // ROLLBACK!
                                // println!("ROLLBACK!");
                                for (i_id, i) in rule.ins[0..i_id].iter().enumerate() {
                                    // println!("... rolling back {:?}", i);
                                    match i {
                                        CreateFromFormula { dest, .. } => {
                                            self.finalize_memo(r, *dest, false)
                                        }
                                        CreateFromCall { dest, .. } => {
                                            self.finalize_memo(r, *dest, false)
                                        }
                                        Check { .. } => {}
                                        MemMove { src, dest } => unimplemented!(),
                                    }
                                }
                                // println!("DID CreateFromCall");
                                continue 'rules;
                            }
                            // println!("Passed check!");
                        }
                    }
                }
                // made it past the instructions! time to commit!
                for q in rule.bit_guard.ready.iter() {
                    self.ready.remove(q);
                }
                for q in rule.bit_assign.empty_mem.iter() {
                    self.mem.remove(q);
                }
                for &q in rule.bit_assign.full_mem.iter() {
                    self.mem.insert(q);
                }
                println!("DO MOVEMENTs!");
                for movement in rule.output.iter() {
                    self.do_movement(r, movement)
                }
                continue 'outer; // reconsider all rules
            }
            // finished all rules
            println!("COORDINATE OVER. READY={:?} MEM={:?}", &self.ready, &self.mem);
            return;
        }
    }

    fn do_movement(&mut self, r: &ProtoR, movement: &Movement) {
        let mut me_ge_iter = movement.me_ge.iter().copied();
        let mut putter_retains = movement.putter_retains;
        let mut putter: LocId = movement.putter;

        // PHASE 1: "take care of mem getters"
        let ps: &PutterSpace = loop {
            // loops exactly once 1 or 2 times
            match &r.spaces[putter.0] {
                Space::PoGe { .. } => panic!("CANNOT BE!"),
                Space::PoPu { ps, mb } => {
                    println!("POPU MOVEMENT");
                    // FINAL or SEMIFINAL LOOP
                    if let Some(mem_0) = me_ge_iter.next() {
                        // SPECIAL CASE! storing external value into protocol memory
                        // re-interpret who is the putter to avoid conflict between:
                        // 1. memory getters are completed BEFORE port getters (by the coordinator)
                        // 2. data movement MUST follow all data clones (or undefined behavior)
                        // 3. we don't yet know if any port-getters want to MOVE (they may want signals)
                        let dest_space = r.spaces[mem_0.0].get_putter_space().unwrap();
                        assert_eq!(dest_space.type_info, ps.type_info);
                        let dest_ptr = unsafe { self.allocator.alloc_uninit(ps.type_info) };
                        println!("ALLOCATED {:p}", dest_ptr);
                        // do the movement, then release the putter with a message
                        if !putter_retains {
                            let src_ptr = ps.ptr.swap(NULL, SeqCst);
                            assert!(src_ptr != NULL);
                            unsafe { ps.type_info.copy(src_ptr, dest_ptr) };
                            mb.send(MsgBox::MOVED_MSG);
                        } else {
                            let src_ptr = ps.ptr.load(SeqCst);
                            assert!(src_ptr != NULL);
                            unsafe { ps.type_info.clone(src_ptr, dest_ptr) };
                            mb.send(MsgBox::UNMOVED_MSG);
                        }
                        assert!(self.ref_counts.insert(dest_ptr as usize, 1).is_none());
                        assert_eq!(NULL, dest_space.ptr.swap(dest_ptr, SeqCst));

                        // mem_0 becomes the putter, and retains the value
                        putter_retains = true;
                        putter = mem_0;
                    } else {
                        // memory taken care of
                        break ps;
                    }
                }
                Space::Memo { ps } => {
                    println!("MEMO MOVEMENT");
                    println!("PTR IS {:p}", ps.ptr.load(SeqCst));
                    // FINAL LOOP
                    // alias the memory in all memory getters. datum itself does not move.
                    let src = ps.ptr.load(SeqCst);
                    assert!(src != NULL);
                    let ref_count: &mut usize = self.ref_counts.get_mut(&(src as usize)).unwrap();
                    for m in me_ge_iter {
                        *ref_count += 1;
                        let getter_space = r.spaces[m.0].get_putter_space().unwrap();
                        assert_eq!(NULL, getter_space.ptr.swap(src, SeqCst));
                    }
                    if movement.po_ge.is_empty() {
                        self.ready.insert(putter); // memory cell is again stable
                        if !putter_retains {
                            // last port getter would clean up, but there isn't one!
                            *ref_count -= 1;
                            assert!(NULL != ps.ptr.swap(NULL, SeqCst));
                            if *ref_count == 0 {
                                // I was the last reference! drop datum IN CIRCUIT
                                self.ref_counts.remove(&(src as usize));
                                self.allocator.drop_inside(src, ps.type_info);
                            }
                        }
                    }
                    break ps;
                }
            }
        };
        // PHASE 2: "take care of port getters"
        println!("releasing getters!");
        println!("PTR IS {:p}", ps.ptr.load(SeqCst));
        if !movement.po_ge.is_empty() {
            ps.rendesvous.move_flags.reset(!putter_retains);
            assert_eq!(
                0,
                ps.rendesvous.countdown.swap(movement.po_ge.len(), SeqCst)
            );
            for po_ge in movement.po_ge.iter().copied() {
                // signal getter, telling them which putter to get from
                r.spaces[po_ge.0].get_msg_box().unwrap().send(putter.0);
            }
        }
    }
}

pub type TraitData = *mut ();
const NULL: TraitData = std::ptr::null_mut();

pub type TraitVtable = *mut ();

#[derive(Debug, Default)]
pub struct Allocator {
    allocated: HashMap<TypeInfo, HashSet<usize>>,
    free: HashMap<TypeInfo, HashSet<usize>>,
}
impl Allocator {
    pub fn store(&mut self, x: Box<dyn PortDatum>) -> bool {
        let (data, info) = unsafe { trait_obj_break(x) };
        self.allocated
            .entry(info)
            .or_insert_with(HashSet::new)
            .insert(data as usize)
    }
    pub unsafe fn alloc_uninit(&mut self, type_info: TypeInfo) -> TraitData {
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
                return data as TraitData;
            }
        }
        // crate a new allocation
        let layout = type_info.get_layout();
        let data = transmute(std::alloc::alloc(layout));
        let success = self.store(trait_obj_build(data, type_info));
        assert!(success);
        data
    }
    pub fn drop_inside(&mut self, data: TraitData, type_info: TypeInfo) -> bool {
        if let Some(set) = self.allocated.get_mut(&type_info) {
            if set.remove(&(data as usize)) {
                unsafe {
                    let mut bx = trait_obj_build(data, type_info);
                    bx.drop_in_place();
                    trait_obj_break(bx);
                }
                let success = self
                    .free
                    .entry(type_info)
                    .or_insert_with(HashSet::new)
                    .insert(data as usize);
                return success;
            }
        }
        false
    }
    pub fn forget_inside(&mut self, data: TraitData, type_info: TypeInfo) -> bool {
        if let Some(set) = self.allocated.get_mut(&type_info) {
            set.remove(&(data as usize))
        } else {
            false
        }
    }
    pub fn remove_free(&mut self, data: TraitData, type_info: TypeInfo) -> bool {
        if let Some(set) = self.free.get_mut(&type_info) {
            set.remove(&(data as usize))
        } else {
            false
        }
    }
}
impl Drop for Allocator {
    fn drop(&mut self) {
        println!("ALLOCATOR DROPPING...");
        // drop all owned values
        for (&vtable, data_vec) in self.allocated.iter() {
            for &data in data_vec.iter() {
                drop(unsafe { trait_obj_build(data as TraitData, vtable) })
            }
        }
        // drop all empty boxes
        let empty_box_vtable = TypeInfo::of::<Box<()>>();
        for (&vtable, data_vec) in self.free.iter() {
            for &data in data_vec.iter() {
                drop(unsafe { trait_obj_build(data as TraitData, empty_box_vtable) });
            }
        }
        println!("ALLOCATOR DROPPING DONE");
    }
}

#[derive(Debug, Default)]
struct MoveFlags {
    move_flags: AtomicU8,
}
impl MoveFlags {
    const MOVE_FLAG_MOVED: u8 = 0b01;
    const MOVE_FLAG_DISABLED: u8 = 0b10;

    #[inline]
    fn type_is_copy_i_moved(&self) {
        self.move_flags.store(Self::MOVE_FLAG_MOVED, SeqCst);
    }

    #[inline]
    fn did_someone_move(&self) -> bool {
        let x: u8 = self.move_flags.load(SeqCst);
        x & Self::MOVE_FLAG_MOVED != 0 && x & Self::MOVE_FLAG_DISABLED == 0
    }

    #[inline]
    fn ask_for_move_permission(&self) -> bool {
        0 == self.move_flags.fetch_or(Self::MOVE_FLAG_MOVED, SeqCst)
    }

    #[inline]
    fn reset(&self, move_enabled: bool) {
        let val = if move_enabled {
            Self::MOVE_FLAG_DISABLED
        } else {
            0
        };
        self.move_flags.store(val, SeqCst);
    }
}

#[derive(DebugStub)]
pub struct Rendesvous {
    countdown: AtomicUsize,
    move_flags: MoveFlags,
    #[debug_stub = "<Semaphore>"]
    mover_sema: Semaphore,
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
                move_flags: MoveFlags::default(),
                mover_sema: Semaphore::new(0),
            },
        }
    }
}

// putters by default retain their da
#[derive(Debug)]
pub struct Rule {
    bit_guard: BitStatePredicate<BitSet>,
    ins: Vec<Instruction<LocId, CallHandle>>, // dummy
    /// COMMITMENTS BELOW HERE
    output: Vec<Movement>,
    // .ready is always identical to bit_guard.ready. use that instead
    bit_assign: BitStatePredicate<()>,
}

#[derive(Debug)]
struct BitStatePredicate<P> {
    ready: P,
    full_mem: BitSet,
    empty_mem: BitSet,
}

#[derive(Debug)]
pub struct Movement {
    putter: LocId,
    me_ge: Vec<LocId>,
    po_ge: Vec<LocId>,
    putter_retains: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct LocId(usize);
impl std::fmt::Debug for LocId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "LocId({})", self.0)
    }
}

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

pub trait PubPortDatum: 'static + Send + Sync {
    const IS_COPY: bool;
    fn my_clone2(&self) -> Self;
    fn my_eq2(&self, other: &Self) -> bool;
}

impl<T: 'static + Clone + PartialEq + Send + Sync> PubPortDatum for T {
    const IS_COPY: bool = false;
    fn my_clone2(&self) -> Self {
        <Self as Clone>::clone(self)
    }
    fn my_eq2(&self, other: &Self) -> bool {
        self == other
    }
}

pub trait PortDatum: Send + Sync {
    fn my_clone(&self, other: TraitData);
    fn my_eq(&self, other: TraitData) -> bool;
    unsafe fn drop_in_place(&mut self);
    fn my_layout(&self) -> Layout;
    fn is_copy(&self) -> bool;
}

impl<T> PortDatum for T
where
    T: PubPortDatum + Copy,
{
    fn is_copy(&self) -> bool {
        true
    }
}
impl<T> PortDatum for T
where
    T: PubPortDatum,
{
    fn my_clone(&self, other: TraitData) {
        let x: *mut Self = unsafe { transmute(other) };
        unsafe { x.write(self.my_clone2()) }
    }
    fn my_eq(&self, other: TraitData) -> bool {
        let x: &Self = unsafe { transmute(other) };
        self.my_eq2(x)
    }
    unsafe fn drop_in_place(&mut self) {
        std::intrinsics::drop_in_place(self)
    }
    fn my_layout(&self) -> Layout {
        Layout::new::<T>()
    }
    default fn is_copy(&self) -> bool {
        <Self as PubPortDatum>::IS_COPY
    }
}

fn main() -> Result<(), (Option<usize>, ProtoBuildError)> {
    use Instruction::*;
    use Term::*;

    let proto = ProtoDef {
        name_defs: hashmap! {
            "A" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<u32>() },
            "B" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<u32>() },
        },
        rules: vec![RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"A", "B"},
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
    let built = build_proto(&proto, MemInitial::default())?;
    Ok(())
}
