
use bidir_map::BidirMap;
use core::{ops::Range, str::FromStr, sync::atomic::AtomicBool};
use debug_stub_derive::DebugStub;
use maplit::{hashmap, hashset};
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::{
    alloc::Layout,
    collections::{HashMap, HashSet},
    fmt,
    mem::{transmute, MaybeUninit},
    sync::{
        atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering::SeqCst},
        Arc,
    },
    time::Duration,
};
use std_semaphore::Semaphore;

pub mod building;

mod allocator;
mod type_info;

mod bit_set;
use bit_set::{BitSet, SetExt};
// #[cfg(test)]
// mod tests;

mod new_tests;

// mod ffi;
// pub use ffi::*;

//////////////////////////////////////////////////////////////////

#[derive(Clone, DebugStub)]
pub struct TypeInfo {
    // essentially a Vtable
    pub layout: Layout,
     #[debug_stub = "write from read"]
    pub raw_move: unsafe fn( *mut u8, *const u8),
    #[debug_stub = "optional clone function pointer"]
    pub maybe_clone: Option<unsafe fn(*mut u8, *const u8)>,
     #[debug_stub = "optional eq function pointer"]
    pub maybe_eq: Option<unsafe fn(*const u8, *const u8) -> bool>,
     #[debug_stub = "optional drop function pointer"]
    pub maybe_drop: Option<unsafe fn(*mut u8)>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct TypeKey(usize);


pub type Name = &'static str;

#[derive(DebugStub, Clone)]
pub struct CallHandle {
    #[debug_stub = "FuncPtr"]
    func: unsafe fn(), // dummy type
    ret: TypeKey,
    args: Vec<TypeKey>,
}

#[derive(Debug)]
pub struct TypeMap {
    pub type_infos: HashMap<TypeKey, TypeInfo>,
    pub bool_type_key: TypeKey,
}
#[derive(Debug, Clone)]
pub enum Term<I, F> {
    True,                                        // returns bool
    False,                                       // returns bool
    Not(Box<Self>),                              // returns bool
    And(Vec<Self>),                              // returns bool
    Or(Vec<Self>),                               // returns bool
    BoolCall { func: F, args: Vec<Term<I, F>> }, // returns bool
    IsEq(TypeKey, Box<[Self; 2]>),              // returns bool
    Named(I),                                    // type of I
}

#[derive(Debug, Clone)]
pub enum Instruction<I, F> {
    CreateFromFormula { dest: I, term: Term<I, F> },
    CreateFromCall { type_key: TypeKey, dest: I, func: F, args: Vec<Term<I, F>> },
    Check(Term<I, F>),
    MemSwap(I, I),
}
#[derive(Debug)]
pub enum Space {
    PoPu { ps: PutterSpace, mb: MsgBox },
    PoGe { mb: MsgBox, type_key: TypeKey },
    Memo { ps: PutterSpace },
}

#[derive(Debug)]
pub struct MsgBox {
    // usize packs two kinds of messages, distinguished by context:
    // 1. identity of the putter (index of putterspace as a usize)
    // 2. whether the putter whether their datum was moved (Msg::MOVED_MSG ^ Msg::UNMOVED_MSG)
    s: crossbeam_channel::Sender<usize>,
    r: crossbeam_channel::Receiver<usize>,
}
#[derive(Debug)]
pub enum ClaimError {
    WrongPortDirection,
    NameRefersToMemoryCell,
    UnknownName,
    AlreadyClaimed,
}
#[derive(Debug)]
pub enum FillMemError {
    NameNotForMemCell,
    UnknownName,
    MemoryNonempty,
    ExpectedType(TypeKey),
}

#[derive(Debug)]
struct PortCommon {
    space_idx: SpaceIndex,
    p: ProtoHandle,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
struct DatumPtr(usize);

#[derive(Debug)]
pub struct Proto {
    cr: Mutex<ProtoCr>,
    r: ProtoR,
}

#[derive(Debug, Clone)]
pub struct ProtoHandle(pub(crate) Arc<Proto>);

pub struct Putter(PortCommon);

pub struct Getter(PortCommon);

#[derive(Debug)]
pub struct ProtoR {
    rules: Vec<Rule>,
    spaces: Vec<Space>,
    perm_space_rng: Range<usize>,
    name_mapping: BidirMap<Name, SpaceIndex>,
    // port_type_key: HashMap<SpaceIndex, (IsPutter, TypeKey)>,
    type_map: Arc<TypeMap>,
}

#[derive(Debug)]
pub struct ProtoCr {
    unclaimed: HashSet<SpaceIndex>,
    ready: BitSet,
    mem: BitSet, // presence means FULL
    allocator: Allocator,
    ref_counts: HashMap<DatumPtr, usize>,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum FinalizeHow {
    DropInside,
    Forget, // was moved out maybe
    Retain,
}

#[derive(Debug)]
pub(crate) struct Allocator {
    occupied: TypedAllocations,
    vacant: TypedAllocations,
    type_map: Arc<TypeMap>,
}

#[derive(Debug, Default)]
pub(crate) struct TypedAllocations {
    map: HashMap<TypeKey, HashSet<DatumPtr>>,
}

#[derive(Debug, Default)]
struct MoveFlags {
    move_flags: AtomicU8,
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
    atomic_datum_ptr: AtomicDatumPtr,
    type_key: TypeKey,
    rendesvous: Rendesvous,
}
#[derive(Debug, Default)]
struct AtomicDatumPtr {
    raw: AtomicPtr<u8>,
}
// putters by default retain their da
#[derive(Debug)]
pub struct Rule {
    bit_guard: BitStatePredicate,
    ins: SmallVec<[Instruction<SpaceIndex, CallHandle>; 4]>, // dummy
    /// COMMITMENTS BELOW HERE
    output: SmallVec<[Movement; 4]>,
    // .ready is always identical to bit_guard.ready. use that instead
    bit_assign: BitStatePredicate,
}

#[derive(Debug)]
struct BitStatePredicate {
    ready: BitSet,
    full_mem: BitSet,
    empty_mem: BitSet,
}

#[derive(Debug)]
pub struct Movement {
    putter: SpaceIndex,
    me_ge: Vec<SpaceIndex>,
    po_ge: Vec<SpaceIndex>,
    putter_retains: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct SpaceIndex(usize);

/////////////////////////////////////////

impl AtomicDatumPtr {
    fn swap(&self, new: DatumPtr) -> DatumPtr {
        DatumPtr::from_raw(self.raw.swap(new.into_raw(), SeqCst))
    }
    fn load(&self) -> DatumPtr {
        DatumPtr::from_raw(self.raw.load(SeqCst))
    }
    fn store(&self, new: DatumPtr) {
        self.raw.store(new.into_raw(), SeqCst)
    }
}
impl DatumPtr {
    const NULL: Self = Self(0);

    fn from_maybe_uninit<T>(m: &mut MaybeUninit<T>) -> Self {
        Self::from_raw(m.as_mut_ptr() as *mut u8)
    }
    fn into_raw(self) -> *mut u8 {
        self.0 as _
    }
    fn from_raw(raw: *mut u8) -> Self {
        Self(raw as _)
    }
}
impl CallHandle {
    unsafe fn exec(&self, dest: DatumPtr, args: &[DatumPtr]) {
        todo!()
    }
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
            Space::PoGe { mb, .. } => Some(mb),
            Space::Memo { .. } => None,
        }
    }
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
        self.s.try_send(msg).expect("SEND BAD");
    }
    pub fn recv(&self) -> usize {
        let msg = self.r.recv().expect("RECV BAD");
        msg
    }
    pub fn recv_timeout(&self, timeout: Duration) -> Option<usize> {
        self.r.recv_timeout(timeout).ok()
    }
}


impl Eq for ProtoHandle {}
impl PartialEq for ProtoHandle {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl PortCommon {

    unsafe fn claim_raw(
        name: Name,
        want_putter: bool,
        p: &ProtoHandle,
    ) -> Result<Self, ClaimError> {
        use ClaimError::*;
        if let Some(space_idx) = p.0.r.name_mapping.get_by_first(&name) {
            let is_putter = match &p.0.r.spaces[space_idx.0] {
                Space::PoGe { .. } => false,
                Space::PoPu { .. } => true,
                Space::Memo { .. } => return Err(ClaimError::NameRefersToMemoryCell),
            };
            if want_putter != is_putter {
                return Err(WrongPortDirection);
            } 
            let mut x = p.0.cr.lock();
            if x.unclaimed.remove(space_idx) {
                let q = Ok(Self { space_idx: *space_idx, p: p.clone() });
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

impl Putter {
    pub unsafe fn claim_raw(p: &ProtoHandle, name: Name) -> Result<Self, ClaimError> {
        Ok(Self(PortCommon::claim_raw(name, true, p)?))
    }

    // This is the real workhorse function
    fn put_inner(&mut self, datum_ptr: DatumPtr) -> bool {
        let Proto { r, cr } = self.0.p.0.as_ref();
        let space = &r.spaces[self.0.space_idx.0];
        if let Space::PoPu { ps, mb } = space {
            assert_eq!(DatumPtr::NULL, ps.atomic_datum_ptr.swap(datum_ptr));
            {
                let mut x = cr.lock();
                assert!(x.ready.insert(self.0.space_idx));
                x.coordinate(r);
            }
            // println!("waiting,...");
            let msg = mb.recv();
            // println!("...got!");
            //DeBUGGY:println!("MSG 0x{:X}", msg);
            ps.atomic_datum_ptr.swap(DatumPtr::NULL);
            match msg {
                MsgBox::MOVED_MSG => true,
                MsgBox::UNMOVED_MSG => false,
                _ => panic!("BAD MSG"),
            }
        } else {
            panic!("WRONG SPACE")
        }
    }

    /// datum_ptr must point to initialized data
    /// returns `true` if the value was consumed, in which case the caller
    ///     is reponsible for forgetting it.
    /// otherwise, returns `false` if the value was not consumed, and should
    ///     still be considered owned and valid.
    pub unsafe fn put_raw(&mut self, src: *mut u8) -> bool {
        // exposed for the sake of C API
        self.put_inner(DatumPtr::from_raw(src))
    }
}


fn get_data<F: FnOnce(FinalizeHow)>(
    r: &ProtoR,
    ps: &PutterSpace,
    maybe_dest: Option<DatumPtr>,
    finalize: F,
) {
    // Do NOT NULLIFY SRC PTR. FINALIZE WILL DO THAT
    // println!("GET DATA");
    let type_info = r.type_map.get_type_info(&ps.type_key);
    let src_ptr = ps.atomic_datum_ptr.load();
    assert!(src_ptr != DatumPtr::NULL);

    const LAST: usize = 1;

    if type_info.is_copy() {
        // irrelevant how many copy
        if let Some(dest_ptr) = maybe_dest {
            unsafe { (type_info.raw_move)(dest_ptr.into_raw(), src_ptr.into_raw()) };
            ps.rendesvous.move_flags.visit();
        }
        let was = ps.rendesvous.countdown.fetch_sub(1, SeqCst);
        if was == LAST {
            let [_, retains] = ps.rendesvous.move_flags.visit();
            let how = if retains { FinalizeHow::Retain } else { FinalizeHow::Forget };
            finalize(how);
        }
    } else {
        if let Some(dest_ptr) = maybe_dest {
            let [visited_first, retains] = ps.rendesvous.move_flags.visit();
            if visited_first && !retains {
                // I move!
                // println!("A");
                let was = ps.rendesvous.countdown.fetch_sub(1, SeqCst);
                // println!("was (A) {}, retains {}", was, retains);
                if was != LAST {
                    ps.rendesvous.mover_sema.acquire();
                }
                unsafe { (type_info.raw_move)(dest_ptr.into_raw(), src_ptr.into_raw()) };
                finalize(FinalizeHow::Forget);
            // println!("/A");
            } else {
                // println!("B");

                    unsafe { (type_info.maybe_clone.expect("NEED CLONE"))(dest_ptr.into_raw(), src_ptr.into_raw()) };
                // do_clone(dest);
                let was = ps.rendesvous.countdown.fetch_sub(1, SeqCst);
                // println!("was (B) {}, retains {}", was, retains);
                if was == LAST {
                    if retains {
                        finalize(FinalizeHow::Retain);
                    } else {
                        // println!("releasing");
                        ps.rendesvous.mover_sema.release();
                    }
                }
                // println!("/B");
            }
        } else {
            // println!("C");
            let was = ps.rendesvous.countdown.fetch_sub(1, SeqCst);
            if was == LAST {
                let [visited_first, retains] = ps.rendesvous.move_flags.visit();
                if visited_first {
                    let how =
                        if retains { FinalizeHow::Retain } else { FinalizeHow::DropInside };
                    finalize(how);
                } else {
                    ps.rendesvous.mover_sema.release();
                }
            }
        }
    }
    // println!("GET COMPLETE");
}
impl Getter {
    pub unsafe fn claim_raw(p: &ProtoHandle, name: Name) -> Result<Self, ClaimError> {
        Ok(Self(PortCommon::claim_raw(name, false, p)?))
    }

    // returns false if it doesn't participate in a rule
    unsafe fn get_inner(
        &mut self,
        maybe_dest: Option<DatumPtr>,
    ) -> bool {
        let Proto { r, cr } = self.0.p.0.as_ref();
        let space = &r.spaces[self.0.space_idx.0];
        if let Space::PoGe { mb, .. } = space {
            {
                let mut x = cr.lock();
                assert!(x.ready.insert(self.0.space_idx));
                x.coordinate(r);
                // TODO check if we can time out
            }
            let putter_id = SpaceIndex(mb.recv());
            // println!("My putter has id {:?}", putter_id);
            match &r.spaces[putter_id.0] {
                Space::PoPu { ps, mb } => get_data(r, ps, maybe_dest, move |how| {
                    // finalization function
                    // println!("FINALIZING PUTTER WITH {}", was_moved);
                    mb.send(match how {
                        FinalizeHow::DropInside | FinalizeHow::Retain => MsgBox::UNMOVED_MSG,
                        FinalizeHow::Forget => MsgBox::MOVED_MSG,
                    })
                    // println!("FINALZIING DONE");
                }),
                Space::Memo { ps } => get_data(r, ps, maybe_dest, |how| {
                    // finalization function
                    //DeBUGGY:println!("was moved? {:?}", was_moved);
                    // println!("FINALIZING MEMO WITH {}", was_moved);
                    self.0.p.0.cr.lock().finalize_memo(r, putter_id, how);
                    // println!("FINALZIING DONE");
                }),
                Space::PoGe { .. } => panic!("CANNOT"),
            };
        } else {
            panic!("am I not a getter?");
        }
        true
    }

    pub unsafe fn get_raw(&mut self, dest: Option<*mut u8>) {
        assert!(self.get_inner( dest.map(DatumPtr::from_raw)));
    }
}

impl ProtoHandle {
    unsafe fn fill_memory_raw<T>(& self, name: Name, type_key: TypeKey, datum: &mut MaybeUninit<T>) -> Result<(), FillMemError> {
        let Proto { r, cr } = self.0.as_ref();
        let type_info = r.type_map.get_type_info(&type_key);
        let space_idx = r.name_mapping.get_by_first(&name).ok_or(FillMemError::UnknownName)?;
        if let Space::Memo { ps } = &r.spaces[space_idx.0] {
            if ps.type_key != type_key {
                return Err(FillMemError::ExpectedType(ps.type_key));
            }
            let mut lock = cr.lock();
            if lock.mem.contains(space_idx) {
                return Err(FillMemError::MemoryNonempty);
            }
            // success guaranteed!
            let datum_ptr = lock.allocator.occupy_allocation(type_key);
            assert_eq!(DatumPtr::NULL, ps.atomic_datum_ptr.swap(datum_ptr));
            lock.mem.insert(*space_idx);
            // println!("SWAP A");
            assert!(lock.ref_counts.insert(datum_ptr, 1).is_none());
             (type_info.raw_move)(datum_ptr.into_raw(), datum.as_ptr() as *const u8) ;
            Ok(())
        } else {
            Err(FillMemError::NameNotForMemCell)
        }
    }
    unsafe fn fill_memory<T>(& self, name: Name, type_key: TypeKey, datum: T) -> Result<(), (T, FillMemError)> {
        let mut datum = MaybeUninit::new(datum);
         self.fill_memory_raw(name, type_key, &mut datum).map_err(|e| {
            (datum.assume_init(), e)
        })
    }
}

impl ProtoR {
    pub fn sanity_check(&self, cr: &ProtoCr) {
        let chunks = cr.ready.data.len();
        assert_eq!(chunks, cr.mem.data.len());
        struct Cap {
            put: bool,
            mem: bool,
            ty: TypeKey,
        }
        let capabilities: Vec<Cap> = self
            .spaces
            .iter()
            .enumerate()
            .map(|(id, x)| match x {
                Space::PoPu { ps, .. } => Cap { put: true, mem: false, ty: ps.type_key },
                Space::PoGe { type_key, .. } => Cap {
                    put: false,
                    mem: false,
                    ty: *type_key,
                },
                Space::Memo { ps } => Cap { put: true, mem: true, ty: ps.type_key },
            })
            .collect();
        for rule in self.rules.iter() {
            assert!(rule.bit_assign.ready.is_subset(&rule.bit_guard.ready));
            assert!(rule.bit_guard.full_mem.is_subset(&rule.bit_guard.ready));
            assert!(rule.bit_guard.empty_mem.is_subset(&rule.bit_guard.ready));

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
                r: &ProtoR,
                capabilities: &Vec<Cap>,
                known_filled: &HashMap<SpaceIndex, bool>,
                term: &Term<SpaceIndex, CallHandle>,
            ) -> TypeKey {
                // TODO do I really need to recurse here??

                use Term::*;
                let tbool = r.type_map.bool_type_key;
                match term {
                    Named(i) => {
                        let cap = &capabilities[i.0];
                        assert_eq!(known_filled[i], true);
                        cap.ty
                    }
                    // MUST BE BOOL
                    True | False => tbool,
                    Not(t) => {
                        assert_eq!(check_and_ret_type(r, capabilities, known_filled, t), tbool);
                        tbool
                    }
                    BoolCall { func, args } => {
                        assert_eq!(func.ret, tbool);
                        assert_eq!(func.args.len(), args.len());
                        for (&t0, term) in func.args.iter().zip(args.iter()) {
                            let t1 = check_and_ret_type(r, &capabilities, &known_filled, term);
                            assert_eq!(t0, t1);
                        }
                        tbool
                    }
                    And(ts) | Or(ts) => {
                        for t in ts.iter() {
                            assert_eq!(check_and_ret_type(r, capabilities, known_filled, t), tbool);
                        }
                        tbool
                    }
                    IsEq(tid, terms) => {
                        assert_eq!(check_and_ret_type(r, capabilities, known_filled, &terms[0]), *tid);
                        assert_eq!(check_and_ret_type(r, capabilities, known_filled, &terms[1]), *tid);
                        tbool
                    }
                }
            }
            for i in rule.ins.iter() {
                match &i {
                    Instruction::Check(term) => assert_eq!(
                        self.type_map.bool_type_key,
                        check_and_ret_type(self, &capabilities, &known_filled, term)
                    ),
                    Instruction::CreateFromCall { type_key, dest, func, args } => {
                        let cap = &capabilities[dest.0];
                        assert!(known_filled.insert(*dest, true).is_none());
                        assert_eq!(*type_key, cap.ty);
                        assert_eq!(func.ret, cap.ty);
                        assert_eq!(func.args.len(), args.len());
                        for (&t0, term) in func.args.iter().zip(args.iter()) {
                            let t1 = check_and_ret_type(self, &capabilities, &known_filled, term);
                            assert_eq!(t0, t1);
                        }
                    }
                    Instruction::CreateFromFormula { dest, term } => {
                        assert!(known_filled.insert(*dest, true).is_none());
                        let cap = &capabilities[dest.0];
                        assert_eq!(cap.ty, check_and_ret_type(self, &capabilities, &known_filled, term))
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
            // make sure everyone whose readiness is UNSET has a means of again
            // becoming ready
            for p in rule.bit_assign.ready.iter() {
                assert!(busy_doing.contains_key(&p));
            }
            // for p in rule.bit_assign.empty_mem.iter().chain(rule.bit_assign.full_mem.iter()) {
            //     assert!(busy_doing.contains_key(&p));
            // }
        }
    }
}

impl ProtoCr {
    fn finalize_memo(&mut self, r: &ProtoR, this_mem_id: SpaceIndex, how: FinalizeHow) {
        // println!("FINALIZING how={:?}", how);
        if how != FinalizeHow::Retain {
            let putter_space = r.spaces[this_mem_id.0].get_putter_space().expect("FINMEM");
            let datum_ptr = putter_space.atomic_datum_ptr.swap(DatumPtr::NULL);
            let ref_count = self.ref_counts.get_mut(&datum_ptr).expect("RC");
            //DeBUGGY:println!("FINALIZING SO {:?} IS READY", this_mem_id);
            assert!(*ref_count > 0);
            *ref_count -= 1;
            if *ref_count == 0 {
                self.ref_counts.remove(&datum_ptr);
                let type_key = r.type_map.get_type_info(&putter_space.type_key);
                if let FinalizeHow::DropInside = how {
                    unsafe { type_key.try_drop_data(datum_ptr) };
                }
                // println!("SWAP B");
                self.allocator.swap_allocation_to(putter_space.type_key, datum_ptr, false);
            }
        }
        if r.perm_space_rng.contains(&this_mem_id.0) {
            self.ready.insert(this_mem_id);
            self.coordinate(r);
        } else {
            // this was a temp memcell. the port behind this thread MUST be ready
            // to fire the SINGLE rule associated with the memcell. Thus, we can
            // safely conclude that we do not need to consider the possibility that
            // this memcell becoming empty will enable some other rule without
            // involving this thread's port.
        }
    }
    fn swap_putter_ptrs(&mut self, r: &ProtoR, a: SpaceIndex, b: SpaceIndex) {
        let pa = r.spaces[a.0].get_putter_space().expect("Pa");
        let pb = r.spaces[b.0].get_putter_space().expect("Pb");
        let olda = pa.atomic_datum_ptr.load();
        let oldb = pb.atomic_datum_ptr.swap(olda);
        pa.atomic_datum_ptr.store(oldb);
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
                // let a = !rule.bit_guard.ready.is_subset(&self.ready);
                // let b = !rule.bit_guard.full_mem.is_subset(&self.mem);
                // let c = !rule.bit_guard.empty_mem.is_disjoint(&self.mem);
                // println!("{:?}", (a,b,c));
                if !rule.bit_guard.ready.is_subset(&self.ready)
                    || !rule.bit_guard.full_mem.is_subset(&self.mem)
                    || !rule.bit_guard.empty_mem.is_disjoint(&self.mem)
                {
                    // println!("failed");
                    // failed guard
                    //DeBUGGY:println!("FAILED G for {:?}. ({}, {}, {})", rule, g1, g2, g3);
                    continue 'rules;
                }
                // println!("DOING A RULE!");
                //DeBUGGY:println!("SUCCESS");
                // //DeBUGGY:println!("going to eval ins for rule {:?}", rule);
                for (i_id, i) in rule.ins.iter().enumerate() {
                    use Instruction::*;
                    match &i {
                        CreateFromFormula { dest, term } => {
                            // MUST BE BOOL. creation ensures it
                            let tbool = r.type_map.bool_type_key;
                            let value = eval_bool(term, r);
                            let dest_ptr = unsafe {
                                let dest_ptr = self.allocator.occupy_allocation(tbool);
                                let q: *mut bool = transmute(dest_ptr);
                                q.write(value);
                                dest_ptr
                            };
                            let old = r.spaces[dest.0]
                                .get_putter_space()
                                .expect("SPf")
                                .atomic_datum_ptr
                                .swap(dest_ptr);
                            assert_eq!(old, DatumPtr::NULL);
                            let was = self.ref_counts.insert(dest_ptr, 1);
                            assert!(was.is_none());
                        }
                        CreateFromCall { type_key, dest, func, args } => {
                            let dest_ptr = self.allocator.occupy_allocation(*type_key);
                            // TODO MAKE LESS CLUNKY
                            let arg_stack =
                                args.iter().map(|arg| eval_ptr(arg, r)).collect::<Vec<_>>();
                            unsafe { func.exec(dest_ptr, &arg_stack[..]) };
                            let old = r.spaces[dest.0]
                                .get_putter_space()
                                .expect("sp2")
                                .atomic_datum_ptr
                                .swap(dest_ptr);
                            assert_eq!(old, DatumPtr::NULL);
                            let was = self.ref_counts.insert(dest_ptr , 1);
                            assert!(was.is_none());
                        }
                        Check(term) => {
                            if !eval_bool(term, r) {
                                // ROLLBACK!
                                // //DeBUGGY:println!("ROLLBACK!");
                                for (_, i) in rule.ins[0..i_id].iter().enumerate().rev() {
                                    // //DeBUGGY:println!("... rolling back {:?}", i);
                                    match i {
                                        CreateFromFormula { dest, .. } => {
                                            self.finalize_memo(r, *dest, FinalizeHow::DropInside)
                                        }
                                        CreateFromCall { dest, .. } => {
                                            self.finalize_memo(r, *dest, FinalizeHow::DropInside)
                                        }
                                        Check(_) => {}
                                        MemSwap(a, b) => self.swap_putter_ptrs(r, *a, *b),
                                    }
                                }
                                // //DeBUGGY:println!("DID CreateFromCall");
                                continue 'rules;
                            }
                            // //DeBUGGY:println!("Passed check!");
                        }
                        MemSwap(a, b) => self.swap_putter_ptrs(r, *a, *b),
                    }
                }
                // made it past the instructions! time to commit!

                // println!("FIRING RULE {:?}", rule);
                self.ready.set_sub(&rule.bit_assign.ready);
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
        let mut putter: SpaceIndex = movement.putter;

        // PHASE 1: "take care of mem getters"
        let ps: &PutterSpace = loop {
            // loops exactly once 1 or 2 times
            match &r.spaces[putter.0] {
                Space::PoGe { .. } => panic!("CANNOT BE!"),
                Space::PoPu { ps, mb } => {
                    let type_info = r.type_map.get_type_info(&ps.type_key);
                    //DeBUGGY:println!("POPU MOVEMENT");
                    // FINAL or SEMIFINAL LOOP
                    if let Some(mem_0) = me_ge_iter.next() {
                        // SPECIAL CASE! storing external value into protocol memory
                        // re-interpret who is the putter to avoid conflict between:
                        // 1. memory getters are completed BEFORE port getters (by the coordinator)
                        // 2. data movement MUST follow all data clones (or undefined behavior)
                        // 3. we don't yet know if any port-getters want to MOVE (they may want signals)
                        let dest_space = r.spaces[mem_0.0].get_putter_space().expect("dest");
                        // assert_eq!(dest_space.type_key, ps.type_key);
                        let dest_ptr = self.allocator.occupy_allocation(ps.type_key);
                        //DeBUGGY:println!("ALLOCATED {:p}", dest_ptr);
                        // do the movement, then release the putter with a message
                        if !putter_retains {
                            let src_ptr = ps.atomic_datum_ptr.swap(DatumPtr::NULL);
                            assert!(src_ptr != DatumPtr::NULL);
                            unsafe { (type_info.raw_move)(dest_ptr.into_raw(), src_ptr.into_raw()) };
                            // unsafe { ps.type_key.copy(src_ptr, dest_ptr) };
                            mb.send(MsgBox::MOVED_MSG);
                        } else {
                            let src_ptr = ps.atomic_datum_ptr.load();
                            assert!(src_ptr != DatumPtr::NULL);

                            unsafe { (type_info.maybe_clone.expect("NO CLONE"))(dest_ptr.into_raw(), src_ptr.into_raw()) };
                            // unsafe { ps.type_key.clone(src_ptr, dest_ptr) };
                            mb.send(MsgBox::UNMOVED_MSG);
                        }
                        assert!(self.ref_counts.insert(dest_ptr , 1).is_none());
                        assert_eq!(DatumPtr::NULL, dest_space.atomic_datum_ptr.swap(dest_ptr));

                        // mem_0 becomes the putter, and retains the value
                        putter_retains = true;
                        putter = mem_0;
                    } else {
                        // memory taken care of
                        if movement.po_ge.is_empty() {
                            // no getters case. do cleanup myself
                            mb.send(MsgBox::UNMOVED_MSG);
                            return;
                        }
                        break ps;
                    }
                }
                Space::Memo { ps } => {
                    //DeBUGGY:println!("MEMO MOVEMENT");
                    //DeBUGGY:println!("PTR IS {:p}", ps.ptr.load(SeqCst));
                    // FINAL LOOP
                    // alias the memory in all memory getters. datum itself does not move.
                    let type_info = r.type_map.get_type_info(&ps.type_key);
                    let src = ps.atomic_datum_ptr.load();
                    assert!(src != DatumPtr::NULL);
                    let ref_count: &mut usize =
                        self.ref_counts.get_mut(&src).expect("eub");
                    for m in me_ge_iter {
                        *ref_count += 1;
                        let getter_space = r.spaces[m.0].get_putter_space().expect("e8h8");
                        assert_eq!(DatumPtr::NULL, getter_space.atomic_datum_ptr.swap(src));
                    }
                    if movement.po_ge.is_empty() {
                        self.ready.insert(putter); // memory cell is again stable
                        if !putter_retains {
                            // last port getter would clean up, but there isn't one!
                            *ref_count -= 1;
                            assert!(DatumPtr::NULL != ps.atomic_datum_ptr.swap(DatumPtr::NULL));
                            if *ref_count == 0 {
                                // I was the last reference! drop datum IN CIRCUIT
                                self.ref_counts.remove(&src);
                                unsafe { type_info.try_drop_data(src) }
                // println!("SWAP C");
                                self.allocator.swap_allocation_to(ps.type_key, src, false);
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
            ps.rendesvous.move_flags.reset(putter_retains);
            assert_eq!(0, ps.rendesvous.countdown.swap(movement.po_ge.len(), SeqCst));
            for po_ge in movement.po_ge.iter().copied() {
                // signal getter, telling them which putter to get from
                r.spaces[po_ge.0].get_msg_box().expect("ueb").send(putter.0);
            }
        }
    }
}

impl MoveFlags {
    const FLAG_VISITED: u8 = 0b01;
    const FLAG_RETAINS: u8 = 0b10;

    fn visit(&self) -> [bool; 2] {
        let val = self.move_flags.fetch_or(Self::FLAG_VISITED, SeqCst);
        let visited_first = val & Self::FLAG_VISITED == 0;
        let retains = val & Self::FLAG_RETAINS != 0;
        [visited_first, retains]
    }

    #[inline]
    fn reset(&self, retains: bool) {
        let val = if retains { Self::FLAG_RETAINS } else { 0 };
        self.move_flags.store(val, SeqCst);
    }
}

impl PutterSpace {
    fn new(type_key: TypeKey) -> Self {
        PutterSpace {
            atomic_datum_ptr: AtomicDatumPtr::default(),
            type_key,
            rendesvous: Rendesvous {
                countdown: 0.into(),
                move_flags: MoveFlags::default(),
                mover_sema: Semaphore::new(0),
            },
        }
    }
}

impl fmt::Debug for SpaceIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SpaceIndex({})", self.0)
    }
}

#[inline]
fn bool_to_ptr(x: bool) -> DatumPtr {
    DatumPtr::from_raw(unsafe { transmute(if x { &true } else { &false }) })
}

fn eval_ptr(term: &Term<SpaceIndex, CallHandle>, r: &ProtoR) -> DatumPtr {
    use Term::*;
    match term {
        Named(i) => r.spaces[i.0].get_putter_space().expect("k").atomic_datum_ptr.load(),
        _ => bool_to_ptr(eval_bool(term, r)),
    }
}
#[inline]
fn ptr_to_bool(x: DatumPtr) -> bool {
    let x: *mut bool = unsafe { transmute(x) };
    unsafe { *x }
}

fn eval_bool(term: &Term<SpaceIndex, CallHandle>, r: &ProtoR) -> bool {
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
        IsEq(type_key, terms) => {
            let ptr0 = eval_ptr(&terms[0], r);
            let ptr1 = eval_ptr(&terms[1], r);
            let type_info = r.type_map.get_type_info(type_key);
            unsafe { (type_info.maybe_eq.expect("no eq!"))(ptr0.into_raw(), ptr1.into_raw()) }
        }
    }
}
