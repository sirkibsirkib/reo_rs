use super::*;

impl PortCommon {
    fn claim_common(
        name: Name,
        want_putter: bool,
        p: &Arc<Proto>,
        type_check: impl FnOnce(TypeKey) -> bool,
    ) -> Result<Self, ClaimError> {
        use ClaimError::*;
        if let Some(space_idx) = p.r.name_mapping.get_by_first(&name) {
            let (is_putter, type_key) = match &p.r.spaces[space_idx.0] {
                Space::PoGe { type_key, .. } => (false, *type_key),
                Space::PoPu { ps, .. } => (true, ps.type_key),
                Space::Memo { .. } => return Err(ClaimError::NameRefersToMemoryCell),
            };
            if !type_check(type_key) {
                return Err(TypeCheckFailed(type_key));
            }
            if want_putter != is_putter {
                return Err(WrongPortDirection);
            }
            let mut x = p.cr.lock();
            if x.unclaimed.remove(space_idx) {
                let q = Ok(Self { space_idx: *space_idx, p: p.clone() });
                q
            } else {
                Err(AlreadyClaimed)
            }
        } else {
            Err(ClaimError::UnknownName)
        }
    }
    fn claim(
        name: Name,
        want_putter: bool,
        p: &Arc<Proto>,
        type_key: TypeKey,
    ) -> Result<Self, ClaimError> {
        Self::claim_common(name, want_putter, p, |k| k == type_key)
    }

    unsafe fn claim_raw(name: Name, want_putter: bool, p: &Arc<Proto>) -> Result<Self, ClaimError> {
        Self::claim_common(name, want_putter, p, |_| true)
    }
}

// impl<T: 'static> TypedGetter<T> {
//     pub fn claim(p: &TypeProtected<ProtoHandle>, name: Name) -> Result<Self, ClaimError> {
//         let getter =
//             Getter(PortCommon::claim(name, false, p.get_inner(), TypeKey::from_type_id::<T>())?);
//         Ok(Self { getter, _phantom: Default::default() })
//     }

//     pub fn get(&mut self) -> T {
//         let mut datum = MaybeUninit::uninit();
//         unsafe { self.getter.get_raw(Some(datum.as_mut_ptr() as *mut u8)) };
//         unsafe { datum.assume_init() }
//     }
//     pub fn get_signal(&mut self) {
//         unsafe { self.getter.get_raw(None) };
//     }
// }
// impl<T: 'static> TypedPutter<T> {
//     pub fn claim(p: &TypeProtected<ProtoHandle>, name: Name) -> Result<Self, ClaimError> {
//         let putter =
//             Putter(PortCommon::claim(name, true, p.get_inner(), TypeKey::from_type_id::<T>())?);
//         Ok(Self { putter, _phantom: Default::default() })
//     }

//     pub fn put_lossy(&mut self, datum: T) -> bool {
//         let mut datum = MaybeUninit::new(datum);
//         let ret = unsafe { self.putter.put_raw(datum.as_mut_ptr() as *mut u8) };
//         if !ret {
//             unsafe { datum.assume_init() };
//         }
//         ret
//     }
//     pub fn try_put(&mut self, datum: T) -> Option<T> {
//         let mut datum = MaybeUninit::new(datum);
//         if unsafe { self.putter.put_raw(datum.as_mut_ptr() as *mut u8) } {
//             None
//         } else {
//             Some(unsafe { datum.assume_init() })
//         }
//     }
// }
impl Putter {
    pub unsafe fn claim_raw(p: &Arc<Proto>, name: Name) -> Result<Self, ClaimError> {
        Ok(Self(PortCommon::claim_raw(name, true, p)?))
    }

    // This is the real workhorse function
    fn put_inner(&mut self, datum_ptr: DatumPtr) -> bool {
        let Proto { r, cr } = self.0.p.as_ref();
        let space = &r.spaces[self.0.space_idx.0];
        if let Space::PoPu { ps, mb, .. } = space {
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
    let type_info = ps.type_key.get_info();
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

                unsafe {
                    (type_info.maybe_clone.expect("NEED CLONE"))(
                        dest_ptr.into_raw(),
                        src_ptr.into_raw(),
                    )
                };
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
                    let how = if retains { FinalizeHow::Retain } else { FinalizeHow::DropInside };
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
    pub unsafe fn claim_raw(p: &Arc<Proto>, name: Name) -> Result<Self, ClaimError> {
        Ok(Self(PortCommon::claim_raw(name, false, p)?))
    }

    // returns false if it doesn't participate in a rule
    unsafe fn get_inner(&mut self, maybe_dest: Option<DatumPtr>) -> bool {
        let Proto { r, cr } = self.0.p.as_ref();
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
                Space::PoPu { ps, mb, .. } => get_data(r, ps, maybe_dest, move |how| {
                    // finalization function
                    // println!("FINALIZING PUTTER WITH {}", was_moved);
                    mb.send(match how {
                        FinalizeHow::DropInside | FinalizeHow::Retain => MsgBox::UNMOVED_MSG,
                        FinalizeHow::Forget => MsgBox::MOVED_MSG,
                    })
                    // println!("FINALZIING DONE");
                }),
                Space::Memo { ps, .. } => get_data(r, ps, maybe_dest, |how| {
                    // finalization function
                    //DeBUGGY:println!("was moved? {:?}", was_moved);
                    // println!("FINALIZING MEMO WITH {}", was_moved);
                    self.0.p.cr.lock().finalize_memo(r, putter_id, how);
                    // println!("FINALZIING DONE");
                }),
                Space::PoGe { .. } => panic!("CANNOT"),
            };
        } else {
            panic!("am I not a getter?");
        }
        true
    }

    /// Null pointer will NOT be written to! Getting a signal rather than a value
    pub unsafe fn get_raw(&mut self, dest: *mut u8) {
        assert!(self.get_inner(if dest.is_null() { None } else { Some(DatumPtr::from_raw(dest)) }));
    }
}

// impl TypeProtected<ProtoHandle> {
//     pub fn fill_memory<T: 'static>(&self, name: Name, datum: T) -> Result<(), FillMemError> {
//         let type_key = TypeKey::from_type_id::<T>();
//         let mut datum = MaybeUninit::new(datum);
//         unsafe {
//             self.0
//                 .fill_memory_common(name, datum.as_mut_ptr() as *mut u8, |t| t == type_key)
//                 .map_err(|e| {
//                     datum.assume_init();
//                     e
//                 })
//         }
//     }
// }
impl Proto {
    unsafe fn fill_memory_common(
        &self,
        name: Name,
        src: *mut u8,
        type_check: impl FnOnce(TypeKey) -> bool,
    ) -> Result<(), FillMemError> {
        let Proto { r, cr } = self;
        let space_idx = r.name_mapping.get_by_first(&name).ok_or(FillMemError::UnknownName)?;
        if let Space::Memo { ps, .. } = &r.spaces[space_idx.0] {
            if !type_check(ps.type_key) {
                return Err(FillMemError::TypeCheckFailed(ps.type_key));
            }
            let mut lock = cr.lock();
            if lock.mem.contains(space_idx) {
                return Err(FillMemError::MemoryNonempty);
            }
            // success guaranteed!
            let datum_ptr = lock.allocator.occupy_allocation(ps.type_key);
            assert_eq!(DatumPtr::NULL, ps.atomic_datum_ptr.swap(datum_ptr));
            lock.mem.insert(*space_idx);
            // println!("SWAP A");
            assert!(lock.ref_counts.insert(datum_ptr, 1).is_none());
            (ps.type_key.get_info().raw_move)(datum_ptr.into_raw(), src);
            Ok(())
        } else {
            Err(FillMemError::NameNotForMemCell)
        }
    }
    pub unsafe fn fill_memory_raw(&self, name: Name, src: *mut u8) -> Result<(), FillMemError> {
        self.fill_memory_common(name, src, |_| true)
    }
}
