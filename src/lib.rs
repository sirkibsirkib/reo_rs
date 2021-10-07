use core::{marker::PhantomData, mem::MaybeUninit};
use debug_stub_derive::DebugStub;

use parking_lot::Mutex;
use smallvec::SmallVec;
use std::{
    alloc::Layout,
    collections::{HashMap, HashSet},
    fmt,
    mem::transmute,
    sync::{
        atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering::SeqCst},
        Arc,
    },
};
use std_semaphore::Semaphore;

// pub mod building;

pub mod building2;

mod allocator;
mod ports;
mod type_info;

mod index_set;
use index_set::{Index as MoverIndex, IndexSet as MoverIndexSet};

//////////////////////////////////////////////////////////////////

pub static BOOL_TYPE_INFO: TypeInfo = TypeInfo {
    layout: Layout::new::<bool>(),
    raw_move: |dest: *mut u8, src: *const u8| {
        let dest = dest as *mut bool;
        let src = src as *const bool;
        unsafe { *dest = *src }
    },
    maybe_clone: None,
    maybe_eq: None,
    maybe_drop: None,
};
pub static BOOL_TYPE_KEY: TypeKey = TypeKey(&BOOL_TYPE_INFO);

// invariant: all TypeKey elements in inner TypeMaps correspond 1-to-1 with std::any::TypeId
pub struct TypeProtected<T>(T);

pub struct TypedPutter<T> {
    putter: Putter,
    _phantom: PhantomData<T>,
}
pub struct TypedGetter<T> {
    getter: Getter,
    _phantom: PhantomData<T>,
}

#[repr(C)]
#[derive(Clone)]
pub struct TypeInfoC {
    // fields constitute a std::alloc::Layout
    pub size: usize,
    pub align: usize,
    pub raw_move: unsafe fn(*mut u8, *const u8), // not nullable
    pub maybe_clone: *mut u8,                    // nullable
    pub maybe_eq: *mut u8,                       // nullable
    pub maybe_drop: *mut u8,                     // nullable
}

#[derive(Clone, DebugStub)]
pub struct TypeInfo {
    pub layout: Layout,
    #[debug_stub = "write from read"]
    pub raw_move: unsafe fn(*mut u8, *const u8),
    #[debug_stub = "optional clone function pointer"]
    pub maybe_clone: Option<unsafe fn(*mut u8, *const u8)>,
    #[debug_stub = "optional eq function pointer"]
    pub maybe_eq: Option<unsafe fn(*const u8, *const u8) -> bool>,
    #[debug_stub = "optional drop function pointer"]
    pub maybe_drop: Option<unsafe fn(*mut u8)>,
}

#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
pub struct TypeKey(pub &'static TypeInfo);

/// invariant: really of type unsafe(*mut R, *const A)
#[derive(Debug)]
pub struct TypedFunction {
    pointer_data: usize,
    ret_type: TypeKey,
    arg_types: Vec<TypeKey>,
}

#[derive(Debug, Clone)]
pub enum Term {
    True,                          // returns bool
    False,                         // returns bool
    Not(Box<Self>),                // returns bool
    And(Vec<Self>),                // returns bool
    Or(Vec<Self>),                 // returns bool
    IsEq(TypeKey, Box<[Self; 2]>), // returns bool
    Named(MoverIndex),             // type of MoverIndex
}

#[derive(Debug, Clone)]
pub enum Instruction {
    CreateFromFormula { dest: MoverIndex, term: Term },
    CreateFromCall { dest: MoverIndex, func: Arc<TypedFunction>, args: Vec<Term> },
    Check(Term),
    MemSwap(MoverIndex, MoverIndex),
}
#[derive(Debug)]
enum MoverSpace {
    PoPu { ps: PutterSpace, mb: MsgBox },
    PoGe { mb: MsgBox, type_key: TypeKey },
    Memo { ps: PutterSpace },
}

#[derive(Debug)]
struct MsgBox {
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
    TypeCheckFailed(TypeKey),
    UnknownName,
    AlreadyClaimed,
}
#[derive(Debug)]
pub enum FillMemError {
    NameNotForMemCell,
    UnknownName,
    MemoryNonempty,
}

#[repr(C)]
#[derive(Debug)]
struct PortCommon {
    p: Arc<Proto>,
    space_idx: MoverIndex,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
struct DatumPtr(usize);

#[derive(Debug)]
pub struct Proto {
    cr: Mutex<ProtoCr>,
    r: ProtoR,
}

#[repr(transparent)]
pub struct Putter(PortCommon);

#[repr(transparent)]
pub struct Getter(PortCommon);

#[derive(Debug)]
pub struct ProtoR {
    rules: Vec<Rule>,
    spaces: Vec<MoverSpace>,
}

#[derive(Debug)]
pub struct ProtoCr {
    unclaimed: HashSet<MoverIndex>,
    ready: MoverIndexSet,
    mem: MoverIndexSet, // presence means FULL
    allocator: Allocator,
    ref_counts: HashMap<DatumPtr, usize>,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum FinalizeHow {
    DropInside,
    Forget, // was moved out maybe
    Retain,
}

#[derive(Debug, Default)]
pub(crate) struct Allocator {
    occupied: TypedAllocations,
    vacant: TypedAllocations,
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
struct PutterSpace {
    atomic_datum_ptr: AtomicDatumPtr,
    type_key: TypeKey,
    rendesvous: Rendesvous,
}
#[derive(Debug, Default)]
struct AtomicDatumPtr {
    raw: AtomicPtr<u8>,
}

#[derive(Debug)]
pub struct Rule {
    bit_guard: BitStatePredicate,
    ins: SmallVec<[Instruction; 3]>,
    /// COMMITMENTS BELOW HERE
    output: SmallVec<[PartitionedMovement; 3]>,
    // .ready is always identical to bit_guard.ready. use that instead
    bit_assign: BitStatePredicate, // TODO make this better
}

#[derive(Debug)]
struct BitStatePredicate {
    ready: MoverIndexSet,
    full_mem: MoverIndexSet,
    empty_mem: MoverIndexSet,
}

#[derive(Debug)]
struct PartitionedMovement {
    putter: MoverIndex,
    me_ge: Vec<MoverIndex>,
    po_ge: Vec<MoverIndex>,
    putter_retains: bool,
}

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
    fn into_raw(self) -> *mut u8 {
        self.0 as _
    }
    fn from_raw(raw: *mut u8) -> Self {
        Self(raw as _)
    }
}
impl TypedFunction {
    unsafe fn exec(&self, dest: DatumPtr, args: &[DatumPtr]) {
        assert_eq!(self.arg_types.len(), args.len());
        let ptr: unsafe fn(*mut u8, *const u8) = transmute(self.pointer_data);
        (ptr)(dest.into_raw(), transmute(args.as_ptr()))
    }
}

impl MoverSpace {
    fn type_key(&self) -> TypeKey {
        match self {
            MoverSpace::PoPu { ps, .. } | MoverSpace::Memo { ps } => ps.type_key,
            MoverSpace::PoGe { type_key, .. } => *type_key,
        }
    }
    fn get_putter_space(&self) -> Option<&PutterSpace> {
        match self {
            MoverSpace::PoPu { ps, .. } => Some(ps),
            MoverSpace::PoGe { .. } => None,
            MoverSpace::Memo { ps } => Some(ps),
        }
    }
    fn get_msg_box(&self) -> Option<&MsgBox> {
        match self {
            MoverSpace::PoPu { mb, .. } => Some(mb),
            MoverSpace::PoGe { mb, .. } => Some(mb),
            MoverSpace::Memo { .. } => None,
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
}

impl ProtoCr {
    fn finalize_memo(&mut self, r: &ProtoR, this_mem_id: MoverIndex, how: FinalizeHow) {
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
                if let FinalizeHow::DropInside = how {
                    unsafe { putter_space.type_key.get_info().try_drop_data(datum_ptr) };
                }
                // println!("SWAP B");
                self.allocator.swap_allocation_to(putter_space.type_key, datum_ptr, false);
            }
        }
        self.ready.insert(this_mem_id);
        self.coordinate(r);
    }
    fn swap_putter_ptrs(&mut self, r: &ProtoR, a: MoverIndex, b: MoverIndex) {
        let pa = r.spaces[a.0].get_putter_space().expect("Pa");
        let pb = r.spaces[b.0].get_putter_space().expect("Pb");
        let olda = pa.atomic_datum_ptr.load();
        let oldb = pb.atomic_datum_ptr.swap(olda);
        pa.atomic_datum_ptr.store(oldb);
    }
    fn coordinate(&mut self, r: &ProtoR) {
        //DeBUGGY:println!("COORDINATE START. READY={:?} MEM={:?}", &self.ready, &self.mem);
        'outer: loop {
            'rules: for rule in r.rules.iter() {
                // let a = !rule.bit_guard.ready.is_subset(&self.ready);
                // let b = !rule.bit_guard.full_mem.is_subset(&self.mem);
                // let c = !rule.bit_guard.empty_mem.is_disjoint(&self.mem);
                // println!("{:?}", (a,b,c));
                if !rule.bit_guard.ready.is_subset_of(&self.ready)
                    || !rule.bit_guard.full_mem.is_subset_of(&self.mem)
                    || !rule.bit_guard.empty_mem.is_disjoint_with(&self.mem)
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
                            let value = eval_bool(term, r);
                            let dest_ptr = unsafe {
                                let dest_ptr = self.allocator.occupy_allocation(BOOL_TYPE_KEY);
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
                        CreateFromCall { dest, func, args } => {
                            let type_key = r.spaces[dest.0].type_key();
                            let dest_ptr = self.allocator.occupy_allocation(type_key);
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
                            let was = self.ref_counts.insert(dest_ptr, 1);
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
                self.ready.remove_all(&rule.bit_assign.ready);
                self.mem.remove_all(&rule.bit_assign.empty_mem);
                self.mem.insert_all(&rule.bit_assign.full_mem);

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

    fn do_movement(&mut self, r: &ProtoR, movement: &PartitionedMovement) {
        let mut me_ge_iter = movement.me_ge.iter().copied();
        let mut putter_retains = movement.putter_retains;
        let mut putter: MoverIndex = movement.putter;

        // PHASE 1: "take care of mem getters"
        let ps: &PutterSpace = loop {
            // loops exactly once 1 or 2 times
            match &r.spaces[putter.0] {
                MoverSpace::PoGe { .. } => panic!("CANNOT BE!"),
                MoverSpace::PoPu { ps, mb } => {
                    let type_info = ps.type_key.get_info();
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
                            unsafe {
                                (type_info.raw_move)(dest_ptr.into_raw(), src_ptr.into_raw())
                            };
                            // unsafe { ps.type_key.copy(src_ptr, dest_ptr) };
                            mb.send(MsgBox::MOVED_MSG);
                        } else {
                            let src_ptr = ps.atomic_datum_ptr.load();
                            assert!(src_ptr != DatumPtr::NULL);

                            unsafe {
                                (type_info.maybe_clone.expect("NO CLONE"))(
                                    dest_ptr.into_raw(),
                                    src_ptr.into_raw(),
                                )
                            };
                            // unsafe { ps.type_key.clone(src_ptr, dest_ptr) };
                            mb.send(MsgBox::UNMOVED_MSG);
                        }
                        assert!(self.ref_counts.insert(dest_ptr, 1).is_none());
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
                MoverSpace::Memo { ps } => {
                    //DeBUGGY:println!("MEMO MOVEMENT");
                    //DeBUGGY:println!("PTR IS {:p}", ps.ptr.load(SeqCst));
                    // FINAL LOOP
                    // alias the memory in all memory getters. datum itself does not move.
                    let type_info = ps.type_key.get_info();
                    let src = ps.atomic_datum_ptr.load();
                    assert!(src != DatumPtr::NULL);
                    let ref_count: &mut usize = self.ref_counts.get_mut(&src).expect("eub");
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

#[inline]
fn bool_to_ptr(x: bool) -> DatumPtr {
    DatumPtr::from_raw(unsafe { transmute(if x { &true } else { &false }) })
}

fn eval_ptr(term: &Term, r: &ProtoR) -> DatumPtr {
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

fn eval_bool(term: &Term, r: &ProtoR) -> bool {
    use Term::*;
    match term {
        // PTR points to BOOL
        Named(_) => ptr_to_bool(eval_ptr(term, r)),
        True => true,
        False => false,
        Not(t) => !eval_bool(t, r),
        And(ts) => ts.iter().all(|t| eval_bool(t, r)),
        Or(ts) => ts.iter().any(|t| eval_bool(t, r)),
        IsEq(type_key, terms) => {
            let ptr0 = eval_ptr(&terms[0], r);
            let ptr1 = eval_ptr(&terms[1], r);
            unsafe {
                (type_key.get_info().maybe_eq.expect("no eq!"))(ptr0.into_raw(), ptr1.into_raw())
            }
        }
    }
}
