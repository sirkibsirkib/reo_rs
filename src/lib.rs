#![feature(raw)]
#![feature(box_patterns)]
#![feature(specialization)]
// #![allow(unused_variables)]
// #![allow(unused_imports)]
// #![allow(dead_code)]

use smallvec::SmallVec;
use std::ops::Range;
use bidir_map::BidirMap;
use core::sync::atomic::AtomicBool;
use debug_stub_derive::DebugStub;
use maplit::{hashmap, hashset};
use parking_lot::Mutex;
use std::{
    fmt,
    alloc::Layout,
    collections::{HashMap, HashSet},
    marker::PhantomData,
    mem::{transmute, MaybeUninit},
    raw::TraitObject,
    sync::{
        atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering::SeqCst},
        Arc,
    },
    time::Duration,
};
use std_semaphore::Semaphore;

mod building;
use building::*;


mod bit_set;
use bit_set::{BitSet, SetExt};

#[cfg(test)]
mod tests;



unsafe impl Send for TypeInfo {}
unsafe impl Sync for TypeInfo {}
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct TypeInfo(pub(crate) TraitVtable);
impl TypeInfo {


    /* Somehow the inlining behaviour of this function sometimes creates DUPLICATE
    trait object vtables in memory. this has ONLY the effect of sometimes causing
    false positives when checking for type-equality (the contents of the vtables are identical)
    ie: TypeInfo::of::<T>() != trait_obj_break(my_box_string)
    Until I figure this out more robustly, I've solved it just by prohibiting inlining
    */
    #[inline(never)]
    pub fn of<T: PortDatum>() -> Self {
        // fabricate the data itself
        let bx: Box<T> = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        // have the compiler insert the correct vtable, using bogus data
        let dy_bx: Box<dyn PortDatum> = bx;
        unsafe  { trait_obj_break(dy_bx).1 }
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
        //DeBUGGY:println!("COPYING with layout {:?}", layout);
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
    let x = TraitObject { data, vtable: info.0 };
    transmute(x)
}

#[inline]
fn trait_obj_read(x: &Box<dyn PortDatum>) -> (TraitData, TypeInfo) {
    let to: &TraitObject = unsafe { transmute(x) };
    (to.data, TypeInfo(to.vtable))
}

unsafe impl Send for CallHandle {}
unsafe impl Sync for CallHandle {}
#[allow(bare_trait_objects)] // DebugStub can't parse the new dyn syntax :(
#[derive(DebugStub, Clone)]
pub struct CallHandle {
    #[debug_stub = "FuncPtr"]
    func: unsafe fn(), // dummy type
    ret: TypeInfo,
    args: Vec<TypeInfo>,
}

pub struct Outputter<T> {
    dest: *mut T,
}
impl<T> Outputter<T> {
    pub fn output(self, t: T) -> OutputToken<T> {
        unsafe { self.dest.write(t) }
        OutputToken { _phantom: Default::default() }
    }
}

/// prevent user creation.
pub struct OutputToken<T> {
    _phantom: PhantomData<T>,
}

/* Call handle can store a function with signature fn(*mut R, *const A0, *const A1)
but expose an API that allows you to input a function with signature fn(Outputter<R>, &A0, &A1) -> OutputToken<R>.
They have the same in-memory representation.
*const T -> &T is safe because ReoRs promises the destination will be valid.

|o| o.output(5);
is identical to
|p| p.write(5);
on the metal,

but the compiler will not compile the former unless the user calls output.
It's essentially a signature of fn() -> R, but for R written using an out pointer
*/
impl CallHandle {
    pub(crate) unsafe fn exec(&self, dest_ptr: TraitData, args: &[TraitData]) {
        let to: unsafe fn() = self.func;
        assert_eq!(self.args.len(), args.len());
        match args.len() {
            0 => {
                let funcy: fn(TraitData) = transmute(to);
                funcy(dest_ptr);
            }
            1 => {
                let funcy: fn(TraitData, TraitData) = transmute(to);
                funcy(dest_ptr, args[0]);
            }
            // TODO
            _ => unreachable!(),
        };
    }
    pub unsafe fn new_nonary_raw<R: PortDatum>(func: fn(*mut R)) -> Self {
        CallHandle { func: transmute(func), ret: TypeInfo::of::<R>(), args: vec![] }
    }
    pub unsafe fn new_unary_raw<R: PortDatum, A0: PortDatum>(func: fn(*mut R, *const A0)) -> Self {
        CallHandle {
            func: transmute(func),
            ret: TypeInfo::of::<R>(),
            args: vec![TypeInfo::of::<A0>()],
        }
    }

    //////////////////
    pub fn new_nonary<R: PortDatum>(func: fn(Outputter<R>) -> OutputToken<R>) -> Self {
        unsafe { Self::new_nonary_raw::<R>(transmute(func)) }
    }

    pub fn new_unary<R: PortDatum, A0: PortDatum>(
        func: fn(Outputter<R>, &A0) -> OutputToken<R>,
    ) -> Self {
        unsafe { Self::new_unary_raw::<R, A0>(transmute(func)) }
    }
    // pub unsafe fn new_binary_raw<R: PortDatum, A0: PortDatum, A1: PortDatum>(
    //     func: Arc<dyn Fn(*mut R, *const A0, *const A1) + Sync>,
    // ) -> Self {
    //     CallHandle {
    //         func: transmute(func),
    //         ret: TypeInfo::of::<R>(),
    //         args: vec![TypeInfo::of::<A0>(), TypeInfo::of::<A1>()],
    //     }
    // }
    // pub unsafe fn new_ternary_raw<R: PortDatum, A0: PortDatum, A1: PortDatum, A2: PortDatum>(
    //     func: Arc<dyn Fn(*mut R, *const A0, *const A1, *const A2) + Sync>,
    // ) -> Self {
    //     CallHandle {
    //         func: transmute(func),
    //         ret: TypeInfo::of::<R>(),
    //         args: vec![TypeInfo::of::<A0>(), TypeInfo::of::<A1>(), TypeInfo::of::<A2>()],
    //     }
    // }
}

pub type Name = &'static str;

#[derive(Debug)]
pub enum Term<I, F> {
    True,                                        // returns bool
    False,                                       // returns bool
    Not(Box<Self>),                              // returns bool
    And(Vec<Self>),                              // returns bool
    Or(Vec<Self>),                               // returns bool
    BoolCall { func: F, args: Vec<Term<I, F>> }, // returns bool
    IsEq(TypeInfo, Box<[Self; 2]>),              // returns bool
    Named(I),                                    // type of I
}

#[derive(Debug)]
pub enum Instruction<I, F> {
    CreateFromFormula { dest: I, term: Term<I, F> },
    CreateFromCall { info: TypeInfo, dest: I, func: F, args: Vec<Term<I, F>> },
    Check { term: Term<I, F> },
    MemSwap(I, I),
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
        //DeBUGGY:println!(">>> sending {:X}", msg);
        self.s.try_send(msg).expect("SEND BAD");
    }
    pub fn recv(&self) -> usize {
        let msg = self.r.recv().expect("RECV BAD");
        //DeBUGGY:println!("<<< recved {:X}", msg);
        msg
    }
    pub fn recv_timeout(&self, timeout: Duration) -> Option<usize> {
        self.r.recv_timeout(timeout).ok()
    }
}

#[derive(Debug)]
pub struct Proto {
    cr: Mutex<ProtoCr>,
    r: ProtoR,
}

impl Eq for ProtoHandle {}
#[derive(Debug, Clone)]
pub struct ProtoHandle(pub(crate) Arc<Proto>);
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
    fn msg_recv(&self, mb: &MsgBox, maybe_timeout: Option<Duration>) -> Option<usize> {
        if let Some(timeout) = maybe_timeout {
            if let Some(msg) = mb.recv_timeout(timeout) {
                return Some(msg);
            } else {
                if self.p.0.cr.lock().ready.remove(&self.id) {
                    return None;
                }
            }
        }
        Some(mb.recv())
    }
    fn claim(
        name: Name,
        want_putter: bool,
        want_type_info: TypeInfo,
        p: &ProtoHandle,
    ) -> Result<Self, ClaimError> {
        use ClaimError::*;
        if let Some(id) = p.0.r.name_mapping.get_by_first(&name) {
            let (is_putter, type_info) = *p.0.r.port_info.get(id).expect("IDK");
            if want_putter != is_putter {
                return Err(WrongPortDirection);
            } else if want_type_info != type_info {
                return Err(TypeMismatch(type_info));
            }
            let mut x = p.0.cr.lock();
            if x.unclaimed.remove(id) {
                let q = Ok(Self { id: *id, type_info, p: p.clone() });
                //DeBUGGY:println!("{:?}", q);
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
        Ok(Self(PortCommon::claim(name, true, TypeInfo::of::<T>(), p)?, Default::default()))
    }

    // returns whether the value was CONSUMED
    pub fn put_entirely(&mut self, ptr: TraitData) -> bool {
        let space = &self.0.p.0.r.spaces[self.0.id.0];
        if let Space::PoPu { ps, mb } = space {
            assert_eq!(NULL, ps.ptr.swap(ptr, SeqCst));
            {
                let mut x = self.0.p.0.cr.lock();
                assert!(x.ready.insert(self.0.id));
                x.coordinate(&self.0.p.0.r);
            }
            //DeBUGGY:println!("waitinig,...");
            let msg = mb.recv();
            //DeBUGGY:println!("...got!");
            //DeBUGGY:println!("MSG 0x{:X}", msg);
            ps.ptr.swap(NULL, SeqCst);
            match msg {
                MsgBox::MOVED_MSG => true,
                MsgBox::UNMOVED_MSG => false,
                _ => panic!("BAD MSG"),
            }
        } else {
            panic!("WRONG SPACE")
        }
    }

    pub fn put(&mut self, mut datum: T) -> Option<T> {
        let ptr: TraitData = unsafe { transmute(&mut datum) };
        if self.put_entirely(ptr) {
            std::mem::forget(datum);
            None
        } else {
            Some(datum)
        }
    }
}
struct Getter<T: PubPortDatum>(PortCommon, PhantomData<T>);
impl<T: PubPortDatum> Getter<T> {
    fn claim(p: &ProtoHandle, name: Name) -> Result<Self, ClaimError> {
        Ok(Self(PortCommon::claim(name, false, TypeInfo::of::<T>(), p)?, Default::default()))
    }

    fn get_data<F: FnOnce(bool)>(
        ps: &PutterSpace,
        maybe_dest: Option<&mut MaybeUninit<T>>,
        finalize: F,
    ) {
        // Do NOT NULLIFY SRC PTR. FINALIZE WILL DO THAT
        //DeBUGGY:println!("GET DATA");
        let ptr: TraitData = ps.ptr.load(SeqCst);
        assert!(ptr != NULL);
        //DeBUGGY:println!("GETTER GOT PTR {:p}", ptr);
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
                //DeBUGGY:println!("I LAST (B)");
                let somebody_moved = ps.rendesvous.move_flags.did_someone_move();
                finalize(somebody_moved);
            }
        } else {
            if let Some(dest) = maybe_dest {
                let won = !ps.rendesvous.move_flags.ask_for_move_permission();
                if won {
                    //DeBUGGY:println!("I WIN (B)");
                    let was = ps.rendesvous.countdown.fetch_sub(1, SeqCst);
                    if was == 1 {
                        do_move(dest);
                    } else {
                        ps.rendesvous.mover_sema.acquire();
                    }
                    finalize(true);
                } else {
                    // lose
                    //DeBUGGY:println!("I LOSE (B)");
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
                    //DeBUGGY:println!("I WIN (C)");
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

    // returns false if it doesn't participate in a rule
    fn get_entirely(
        &mut self,
        maybe_timeout: Option<Duration>,
        maybe_dest: Option<&mut MaybeUninit<T>>,
    ) -> bool {
        let space = &self.0.p.0.r.spaces[self.0.id.0];
        if let Space::PoGe { mb } = space {
            {
                let mut x = self.0.p.0.cr.lock();
                assert!(x.ready.insert(self.0.id));
                x.coordinate(&self.0.p.0.r);
            }
            let putter_id = match self.0.msg_recv(mb, maybe_timeout) {
                None => return false,
                Some(msg) => LocId(msg),
            };
            match &self.0.p.0.r.spaces[putter_id.0] {
                Space::PoPu { ps, mb } => Self::get_data(ps, maybe_dest, move |was_moved| {
                    // finalization function
                    if was_moved {
                        assert!(NULL != ps.ptr.swap(NULL, SeqCst));
                        mb.send(MsgBox::MOVED_MSG)
                    } else {
                        mb.send(MsgBox::UNMOVED_MSG)
                    };
                }),
                Space::Memo { ps } => Self::get_data(ps, maybe_dest, |was_moved| {
                    // finalization function
                    //DeBUGGY:println!("was moved? {:?}", was_moved);
                    self.0.p.0.cr.lock().finalize_memo(&self.0.p.0.r, putter_id, was_moved);
                }),
                Space::PoGe { .. } => panic!("CANNOT"),
            };
        } else {
            panic!("am I not a getter?");
        }
        true
    }

    pub fn get(&mut self) -> T {
        let mut ret = MaybeUninit::uninit();
        assert!(self.get_entirely(None, Some(&mut ret)));
        unsafe { ret.assume_init() }
    }
    pub fn get_timeout(&mut self, timeout: Duration) -> Option<T> {
        let mut ret = MaybeUninit::uninit();
        if self.get_entirely(Some(timeout), Some(&mut ret)) {
            Some(unsafe { ret.assume_init() })
        } else {
            None
        }
    }
    pub fn get_signal(&mut self) {
        assert!(self.get_entirely(None, None));
    }
    pub fn get_signal_timeout(&mut self, timeout: Duration) -> bool {
        self.get_entirely(Some(timeout), None)
    }
}

#[derive(Debug)]
pub struct ProtoR {
    rules: Vec<Rule>,
    spaces: Vec<Space>,
    perm_space_rng: Range<usize>,
    name_mapping: BidirMap<Name, LocId>,
    port_info: HashMap<LocId, (IsPutter, TypeInfo)>,
}
impl ProtoR {
    pub fn sanity_check(&self, cr: &ProtoCr) {
        let chunks = cr.ready.data.len();
        assert_eq!(chunks, cr.mem.data.len());
        struct Cap {
            put: bool,
            mem: bool,
            ty: TypeInfo,
        };
        let capabilities: Vec<Cap> = self
            .spaces
            .iter()
            .enumerate()
            .map(|(id, x)| match x {
                Space::PoPu { ps, .. } => Cap { put: true, mem: false, ty: ps.type_info },
                Space::PoGe { .. } => {
                    Cap { put: false, mem: false, ty: self.port_info.get(&LocId(id)).expect("BADCAP").1 }
                }
                Space::Memo { ps } => Cap { put: true, mem: true, ty: ps.type_info },
            })
            .collect();
        for (k, (putter, tinfo)) in self.port_info.iter() {
            let cap = &capabilities[k.0];
            assert!(!cap.mem);
            assert_eq!(cap.put, *putter);
            assert_eq!(cap.ty, *tinfo);
        }
        for rule in self.rules.iter() {
            assert_eq!(chunks, rule.bit_guard.ready.data.len());
            assert_eq!(chunks, rule.bit_guard.empty_mem.data.len());
            assert_eq!(chunks, rule.bit_guard.full_mem.data.len());
            assert_eq!(chunks, rule.bit_assign.full_mem.data.len());
            assert_eq!(chunks, rule.bit_assign.empty_mem.data.len());
            let mut known_filled = hashmap! {};
            for x in rule.bit_guard.ready.iter() {
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
            fn check_and_ret_type(
                capabilities: &Vec<Cap>,
                known_filled: &HashMap<LocId, bool>,
                term: &Term<LocId, CallHandle>,
            ) -> TypeInfo {
                // TODO do I really need to recurse here??

                use Term::*;
                let tbool = TypeInfo::of::<bool>();
                match term {
                    Named(i) => {
                        let cap = &capabilities[i.0];
                        assert_eq!(known_filled[i], true);
                        cap.ty
                    }
                    // MUST BE BOOL
                    True | False => tbool,
                    Not(t) => {
                        assert_eq!(check_and_ret_type(capabilities, known_filled, t), tbool);
                        tbool
                    }
                    BoolCall { func, args } => {
                        assert_eq!(func.ret, tbool);
                        assert_eq!(func.args.len(), args.len());
                        for (&t0, term) in func.args.iter().zip(args.iter()) {
                            let t1 = check_and_ret_type(&capabilities, &known_filled, term);
                            assert_eq!(t0, t1);
                        }
                        tbool
                    }
                    And(ts) | Or(ts) => {
                        for t in ts.iter() {
                            assert_eq!(check_and_ret_type(capabilities, known_filled, t), tbool);
                        }
                        tbool
                    }
                    IsEq(tid, terms) => {
                        assert_eq!(check_and_ret_type(capabilities, known_filled, &terms[0]), *tid);
                        assert_eq!(check_and_ret_type(capabilities, known_filled, &terms[1]), *tid);
                        tbool
                    }
                }
            }
            for i in rule.ins.iter() {
                match &i {
                    Instruction::Check { term } => assert_eq!(
                        TypeInfo::of::<bool>(),
                        check_and_ret_type(&capabilities, &known_filled, term)
                    ),
                    Instruction::CreateFromCall { info, dest, func, args } => {
                        let cap = &capabilities[dest.0];
                        assert!(known_filled.insert(*dest, true).is_none());
                        assert_eq!(*info, cap.ty);
                        assert_eq!(func.ret, cap.ty);
                        assert_eq!(func.args.len(), args.len());
                        for (&t0, term) in func.args.iter().zip(args.iter()) {
                            let t1 = check_and_ret_type(&capabilities, &known_filled, term);
                            assert_eq!(t0, t1);
                        }
                    }
                    Instruction::CreateFromFormula { dest, term } => {
                        assert!(known_filled.insert(*dest, true).is_none());
                        let cap = &capabilities[dest.0];
                        assert_eq!(cap.ty, check_and_ret_type(&capabilities, &known_filled, term))
                    }
                    Instruction::MemSwap(a, b) => {
                        let a_knowledge = known_filled.remove(a);
                        let b_knowledge = known_filled.remove(b);
                        if let Some(x) = a_knowledge {
                            known_filled.insert(*b, x);
                        }
                        if let Some(x) = b_knowledge {
                            known_filled.insert(*a, x);
                        }
                    }
                }
            }
            let mut busy_doing = hashmap! {}; // => true for put, => false for get
            for movement in rule.output.iter() {
                let p = movement.putter;
                //DeBUGGY:println!("MV {:?}", movement);
                assert_eq!(known_filled.get(&p), Some(&true));
                let cap = &capabilities[p.0];
                assert!(busy_doing.insert(p, true).is_none());

                assert_eq!(
                    self.perm_space_rng.contains(&p.0) && cap.mem && !movement.putter_retains,
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
            // make sure everyone in READY set is covered
            // YES even mem cells that are not consumed. this just sets them to READY
            for p in rule.bit_guard.ready.iter() {
                assert!(busy_doing.contains_key(&p));
            }
            // todo check NON putters in assignment set
            for p in
                rule.bit_assign.empty_mem.iter().chain(rule.bit_assign.full_mem.iter())
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
        let putter_space = r.spaces[this_mem_id.0].get_putter_space().expect("FINMEM");
        let ptr = putter_space.ptr.swap(NULL, SeqCst);
        let ref_count = self.ref_counts.get_mut(&(ptr as usize)).expect("RC");
        //DeBUGGY:println!("FINALIZING SO {:?} IS READY", this_mem_id);
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
        if r.perm_space_rng.contains(&this_mem_id.0) {
            self.ready.insert(this_mem_id);
            self.coordinate(r);
        } else {
            // this was a temp memcell
        }
    }
    fn swap_putter_ptrs(&mut self, r: &ProtoR, a: LocId, b: LocId) {
        let pa = r.spaces[a.0].get_putter_space().expect("Pa");
        let pb = r.spaces[b.0].get_putter_space().expect("Pb");
        let olda = pa.ptr.load(SeqCst);
        let oldb = pb.ptr.swap(olda, SeqCst);
        pa.ptr.store(oldb, SeqCst);
        // if r.perm_space_rng.contains(&a.0) {
        //     self.ready.insert(a);
        // }
        // if r.perm_space_rng.contains(&a.0) {
        //     self.ready.insert(b);
        // }
    }
    fn coordinate(&mut self, r: &ProtoR) {
        //DeBUGGY:println!("COORDINATE START. READY={:?} MEM={:?}", &self.ready, &self.mem);
        'outer: loop {
            'rules: for rule in r.rules.iter() {
                let g1 = rule.bit_guard.ready.is_subset(&self.ready);
                let g2 = rule.bit_guard.full_mem.is_subset(&self.mem);
                let g3 = rule.bit_guard.empty_mem.is_disjoint(&self.mem);
                if !(g1 && g2 && g3) {
                    // failed guard
                    //DeBUGGY:println!("FAILED G for {:?}. ({}, {}, {})", rule, g1, g2, g3);
                    continue 'rules;
                }
                //DeBUGGY:println!("SUCCESS");
                // //DeBUGGY:println!("going to eval ins for rule {:?}", rule);
                for (i_id, i) in rule.ins.iter().enumerate() {
                    use Instruction::*;
                    match &i {
                        CreateFromFormula { dest, term } => {
                            // MUST BE BOOL. creation ensures it
                            let tbool = TypeInfo::of::<bool>();
                            let value = eval_bool(term, r);
                            let dest_ptr = unsafe {
                                let dest_ptr = self.allocator.alloc_uninit(tbool);
                                let q: *mut bool = transmute(dest_ptr);
                                q.write(value);
                                dest_ptr
                            };
                            let old = r.spaces[dest.0]
                                .get_putter_space()
                                .expect("SPf")
                                .ptr
                                .swap(dest_ptr, SeqCst);
                            assert_eq!(old, NULL);
                            let was = self.ref_counts.insert(dest_ptr as usize, 1);
                            assert!(was.is_none());
                        }
                        CreateFromCall { info, dest, func, args } => {
                            let dest_ptr = unsafe { self.allocator.alloc_uninit(*info) };
                            // TODO MAKE LESS CLUNKY
                            let arg_stack =
                                args.iter().map(|arg| eval_ptr(arg, r)).collect::<Vec<_>>();
                            unsafe { func.exec(dest_ptr, &arg_stack[..]) };
                            let old = r.spaces[dest.0]
                                .get_putter_space()
                                .expect("sp2")
                                .ptr
                                .swap(dest_ptr, SeqCst);
                            assert_eq!(old, NULL);
                            let was = self.ref_counts.insert(dest_ptr as usize, 1);
                            assert!(was.is_none());
                        }
                        Check { term } => {
                            if !eval_bool(term, r) {
                                // ROLLBACK!
                                // //DeBUGGY:println!("ROLLBACK!");
                                for (_, i) in rule.ins[0..i_id].iter().enumerate().rev() {
                                    // //DeBUGGY:println!("... rolling back {:?}", i);
                                    match i {
                                        CreateFromFormula { dest, .. } => {
                                            self.finalize_memo(r, *dest, false)
                                        }
                                        CreateFromCall { dest, .. } => {
                                            self.finalize_memo(r, *dest, false)
                                        }
                                        Check { .. } => {}
                                        MemSwap(a,b) => self.swap_putter_ptrs(r, *a, *b),
                                    }
                                }
                                // //DeBUGGY:println!("DID CreateFromCall");
                                continue 'rules;
                            }
                            // //DeBUGGY:println!("Passed check!");
                        }
                        MemSwap(a,b) => self.swap_putter_ptrs(r, *a, *b),
                    }
                }
                // made it past the instructions! time to commit!
                self.ready.set_sub(&rule.bit_guard.ready);
                self.mem.set_sub(&rule.bit_assign.empty_mem);
                self.mem.set_add(&rule.bit_assign.full_mem);

                //DeBUGGY:println!("DO MOVEMENTs!");
                for movement in rule.output.iter() {
                    self.do_movement(r, movement)
                }
                continue 'outer; // reconsider all rules
            }
            // finished all rules
            //DeBUGGY:println!("COORDINATE OVER. READY={:?} MEM={:?}", &self.ready, &self.mem);
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
                    //DeBUGGY:println!("POPU MOVEMENT");
                    // FINAL or SEMIFINAL LOOP
                    if let Some(mem_0) = me_ge_iter.next() {
                        // SPECIAL CASE! storing external value into protocol memory
                        // re-interpret who is the putter to avoid conflict between:
                        // 1. memory getters are completed BEFORE port getters (by the coordinator)
                        // 2. data movement MUST follow all data clones (or undefined behavior)
                        // 3. we don't yet know if any port-getters want to MOVE (they may want signals)
                        let dest_space = r.spaces[mem_0.0].get_putter_space().expect("dest");
                        assert_eq!(dest_space.type_info, ps.type_info);
                        let dest_ptr = unsafe { self.allocator.alloc_uninit(ps.type_info) };
                        //DeBUGGY:println!("ALLOCATED {:p}", dest_ptr);
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
                    //DeBUGGY:println!("MEMO MOVEMENT");
                    //DeBUGGY:println!("PTR IS {:p}", ps.ptr.load(SeqCst));
                    // FINAL LOOP
                    // alias the memory in all memory getters. datum itself does not move.
                    let src = ps.ptr.load(SeqCst);
                    assert!(src != NULL);
                    let ref_count: &mut usize = self.ref_counts.get_mut(&(src as usize)).expect("eub");
                    for m in me_ge_iter {
                        *ref_count += 1;
                        let getter_space = r.spaces[m.0].get_putter_space().expect("e8h8");
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
        //DeBUGGY:println!("releasing getters!");
        //DeBUGGY:println!("PTR IS {:p}", ps.ptr.load(SeqCst));
        if !movement.po_ge.is_empty() {
            ps.rendesvous.move_flags.reset(!putter_retains);
            assert_eq!(0, ps.rendesvous.countdown.swap(movement.po_ge.len(), SeqCst));
            for po_ge in movement.po_ge.iter().copied() {
                // signal getter, telling them which putter to get from
                r.spaces[po_ge.0].get_msg_box().expect("ueb").send(putter.0);
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
        self.allocated.entry(info).or_insert_with(HashSet::new).insert(data as usize)
    }
    pub unsafe fn alloc_uninit(&mut self, type_info: TypeInfo) -> TraitData {
        if let Some(set) = self.free.get_mut(&type_info) {
            // re-using freed
            if let Some(data) = set.iter().copied().next() {
                set.remove(&data);
                let success =
                    self.allocated.entry(type_info).or_insert_with(HashSet::new).insert(data);
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
                let success =
                    self.free.entry(type_info).or_insert_with(HashSet::new).insert(data as usize);
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
        //DeBUGGY:println!("ALLOCATOR DROPPING...");
        // drop all owned values
        for (&vtable, data_vec) in self.allocated.iter() {
            for &data in data_vec.iter() {
                drop(unsafe { trait_obj_build(data as TraitData, vtable) })
            }
        }
        // drop all empty boxes
        let empty_box_vtable = TypeInfo::of::<Box<()>>();
        for (_, data_vec) in self.free.iter() {
            for &data in data_vec.iter() {
                drop(unsafe { trait_obj_build(data as TraitData, empty_box_vtable) });
            }
        }
        //DeBUGGY:println!("ALLOCATOR DROPPING DONE");
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
        let val = if move_enabled { Self::MOVE_FLAG_DISABLED } else { 0 };
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
    ins: SmallVec<[Instruction<LocId, CallHandle>;4]>, // dummy
    /// COMMITMENTS BELOW HERE
    output: SmallVec<[Movement;4]>,
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
impl fmt::Debug for LocId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LocId({})", self.0)
    }
}

// type BitSet = HashSet<LocId>;

#[inline]
fn bool_to_ptr(x: bool) -> TraitData {
    unsafe { transmute(if x { &true } else { &false }) }
}

fn eval_ptr(term: &Term<LocId, CallHandle>, r: &ProtoR) -> TraitData {
    use Term::*;
    match term {
        Named(i) => r.spaces[i.0].get_putter_space().expect("k").ptr.load(SeqCst),
        _ => bool_to_ptr(eval_bool(term, r)),
    }
}
#[inline]
fn ptr_to_bool(x: TraitData) -> bool {
    let x: *mut bool = unsafe { transmute(x) };
    unsafe { *x }
}

fn eval_bool(term: &Term<LocId, CallHandle>, r: &ProtoR) -> bool {
    use Term::*;
    match term {
        // PTR points to BOOL
        Named(_) => ptr_to_bool(eval_ptr(term, r)),
        // INHERENTLY BOOL
        BoolCall { func, args } => {
            let mut ret: AtomicBool = false.into();
            // TODO make this less clunky
            let args = args.iter().map(|arg| eval_ptr(arg, r)).collect::<Vec<_>>();
            let p = &mut ret;
            unsafe {
                let p = transmute(p);
                func.exec(p, &args[..]);
                ret.load(SeqCst)
            }
        }
        True => true,
        False => false,
        Not(t) => !eval_bool(t, r),
        And(ts) => ts.iter().all(|t| eval_bool(t, r)),
        Or(ts) => ts.iter().any(|t| eval_bool(t, r)),
        IsEq(info, terms) => {
            let ptr0 = eval_ptr(&terms[0], r);
            let ptr1 = eval_ptr(&terms[1], r);
            let to: &dyn PortDatum =
                unsafe { transmute(TraitObject { data: ptr0, vtable: info.0 }) };
            to.my_eq(ptr1)
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

pub trait PortDatum: Send + Sync + 'static {
    fn my_clone(&self, other: TraitData);
    fn my_eq(&self, other: TraitData) -> bool;
    unsafe fn drop_in_place(&mut self);
    fn my_layout(&self) -> Layout;
    fn is_copy(&self) -> bool;
}

impl<T: PubPortDatum + Copy> PortDatum for T {
    fn is_copy(&self) -> bool {
        true
    }
}

impl<T: PubPortDatum> PortDatum for T {
    fn my_clone(&self, other: TraitData) {
        let x: *mut Self = unsafe { transmute(other) };
        unsafe { x.write(self.my_clone2()) }
    }
    default fn my_eq(&self, other: TraitData) -> bool {
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
