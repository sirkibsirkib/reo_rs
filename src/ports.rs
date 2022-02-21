use super::*;

impl PortCommon {
    fn claim(mover_index: Index, want_putter: bool, p: &Arc<Proto>) -> Result<Self, ClaimError> {
        let space_idx = mover_index;
        use ClaimError as Ce;
        let is_putter = match p.r.spaces.get(space_idx).ok_or(Ce::UnknownName)? {
            MoverSpace::PoGe { .. } => false,
            MoverSpace::PoPu { .. } => true,
            MoverSpace::Memo { .. } => return Err(Ce::NameRefersToMemoryCell),
        };
        if want_putter != is_putter {
            return Err(Ce::WrongPortDirection);
        }
        let mut x = p.cr.lock();
        if x.unclaimed.remove(space_idx) {
            let q = Ok(Self { space_idx, p: p.clone() });
            q
        } else {
            Err(Ce::AlreadyClaimed)
        }
    }
    fn type_key(&self) -> TypeKey {
        let Proto { r, .. } = self.p.as_ref();
        r.spaces[self.space_idx].type_key()
    }
}

impl Putter {
    pub fn type_key(&self) -> TypeKey {
        self.0.type_key()
    }
    pub fn claim(p: &Arc<Proto>, mover_index: Index) -> Result<Self, ClaimError> {
        Ok(Self(PortCommon::claim(mover_index, true, p)?))
    }

    // This is the real workhorse function
    fn put_inner(&mut self, datum_ptr: DatumPtr) -> bool {
        let Proto { r, cr } = self.0.p.as_ref();
        let space = &r.spaces[self.0.space_idx];
        if let MoverSpace::PoPu { ps, mb, .. } = space {
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

    // pub unsafe fn put_typed<T>(&mut self, src: &mut MaybeUninit<T>) -> bool {
    //     self.put_inner(DatumPtr::from_raw(src.as_mut_ptr() as *mut u8))
    // }

    // pub unsafe fn lossy_put<T>(&mut self, datum: T) -> bool {
    //     let mut datum = MaybeUninit::new(datum);
    //     let consumed = self.put_typed(&mut datum);
    //     if !consumed {
    //         datum.as_mut_ptr().drop_in_place();
    //     }
    //     consumed
    // }
}

impl Getter {
    fn get_data<F: FnOnce(FinalizeHow)>(
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
    pub fn type_key(&self) -> TypeKey {
        self.0.type_key()
    }
    pub fn claim(p: &Arc<Proto>, mover_index: Index) -> Result<Self, ClaimError> {
        Ok(Self(PortCommon::claim(mover_index, false, p)?))
    }

    // returns false if it doesn't participate in a rule
    unsafe fn get_inner(&mut self, maybe_dest: Option<DatumPtr>) -> bool {
        let Proto { r, cr } = self.0.p.as_ref();
        let space = &r.spaces[self.0.space_idx];
        if let MoverSpace::PoGe { mb, .. } = space {
            {
                let mut x = cr.lock();
                assert!(x.ready.insert(self.0.space_idx));
                x.coordinate(r);
                // TODO check if we can time out
            }
            let putter_id: Index = mb.recv();
            // println!("My putter has id {:?}", putter_id);
            match &r.spaces[putter_id] {
                MoverSpace::PoPu { ps, mb, .. } => Self::get_data(&ps, maybe_dest, move |how| {
                    // finalization function
                    // println!("FINALIZING PUTTER WITH {}", was_moved);
                    mb.send(match how {
                        FinalizeHow::DropInside | FinalizeHow::Retain => MsgBox::UNMOVED_MSG,
                        FinalizeHow::Forget => MsgBox::MOVED_MSG,
                    })
                    // println!("FINALZIING DONE");
                }),
                MoverSpace::Memo { ps, .. } => Self::get_data(&ps, maybe_dest, |how| {
                    // finalization function
                    //DeBUGGY:println!("was moved? {:?}", was_moved);
                    // println!("FINALIZING MEMO WITH {}", was_moved);
                    self.0.p.cr.lock().finalize_memo(r, putter_id, how);
                    // println!("FINALZIING DONE");
                }),
                MoverSpace::PoGe { .. } => panic!("CANNOT"),
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

    // pub unsafe fn get_typed<T>(&mut self) -> T {
    //     let mut data = MaybeUninit::<T>::uninit();
    //     self.get_raw(data.as_mut_ptr() as *mut u8);
    //     data.assume_init()
    // }

    pub fn get_signal(&mut self) {
        unsafe { self.get_raw(core::ptr::null_mut()) }
    }
}
