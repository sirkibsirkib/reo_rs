use super::*;

#[repr(C)]
#[derive(Default)]
pub struct MemInitial {
    strg: HashMap<Name, Box<dyn PortDatum>>,
}
impl MemInitial {
    #[inline]
    pub fn with<T: PubPortDatum>(mut self, name: Name, init: T) -> Self {
        let dy: Box<dyn PortDatum> = Box::new(init);
        let i1 = TypeInfo::of::<T>();
        // TODO for some reason Rustc makes two trait objects?
        // Anyway we exclusively use those returned by TypeInfo
        let (d, _i2) = unsafe { trait_obj_break(dy) };
        let dy = unsafe { trait_obj_build(d, i1) };
        self.strg.insert(name, dy);
        self
    }
}

#[derive(Debug)]
pub enum NameDef {
    Port { is_putter: bool, type_info: TypeInfo },
    Mem(TypeInfo),
    Func(CallHandle),
}

#[repr(C)]
#[derive(Debug)]
pub struct ProtoDef {
    pub name_defs: HashMap<Name, NameDef>,
    pub rules: Vec<RuleDef>,
}

#[derive(Debug)]
pub struct StatePredicate {
    pub ready_ports: HashSet<Name>,
    pub full_mem: HashSet<Name>,
    pub empty_mem: HashSet<Name>,
}
#[derive(Debug)]
pub struct RuleDef {
    pub state_guard: StatePredicate,
    pub ins: Vec<Instruction<Name, Name>>,
    pub output: HashMap<Name, (bool, HashSet<Name>)>,
}
/////////////////////////////////////

#[derive(Debug)]
pub enum ProtoBuildError {
    PutWithoutFullCertainty { name: Name },
    GetWithoutEmptyCertainty { name: Name },
    ReadWithoutFullCertainty { name: Name },
    PutterCannotGet { name: Name },
    UndefinedLocName { name: Name },
    UndefinedFuncName { name: Name },
    TermNameIsNotPutter { name: Name },
    EqForDifferentTypes,
    GetterHasMuliplePutters { name: Name },
    GetterHasNoPutters { name: Name },
    PortInMemPremise { name: Name },
    MemInPortPremise { name: Name },
    ConflictingMemPremise { name: Name },
    InstructionShadowsName { name: Name },
    CheckingNonBoolType,
    CreatingNonBoolFromFormula,
    InitialTypeMismatch { name: Name },
    MovementTypeMismatch { getter: Name, putter: Name },
    InstructionCannotOverwrite { name: Name }, // todo get more sophisticated
    CanOnlySwapMemory { name: Name },
}

fn resolve_full(
    temp_names: &HashMap<Name, (LocId, TypeInfo)>,
    name_mapping: &BidirMap<Name, LocId>,
    name: Name,
) -> Result<LocId, ProtoBuildError> {
    use ProtoBuildError::*;
    temp_names
        .get(&name)
        .map(|x| x.0)
        .or_else(|| name_mapping.get_by_first(&name).copied())
        .ok_or(UndefinedLocName { name })
}

fn term_eval_tid(
    spaces: &Vec<Space>,
    temp_names: &HashMap<Name, (LocId, TypeInfo)>,
    name_mapping: &BidirMap<Name, LocId>,
    term: &Term<Name, Name>,
) -> Result<TypeInfo, ProtoBuildError> {
    use ProtoBuildError::*;
    use Term::*;
    Ok(match term {
        Named(name) => {
            spaces[resolve_full(temp_names, name_mapping, name)?.0]
                .get_putter_space()
                .ok_or(TermNameIsNotPutter { name })?
                .type_info
        }
        _ => TypeInfo::of::<bool>(),
    })
}

fn term_convert(
    spaces: &Vec<Space>,
    temp_names: &HashMap<Name, (LocId, TypeInfo)>,
    name_mapping: &BidirMap<Name, LocId>,
    call_handles: &HashMap<Name, CallHandle>,
    known_state: &HashMap<Name, bool>,
    term: &Term<Name, Name>,
) -> Result<Term<LocId, CallHandle>, ProtoBuildError> {
    use ProtoBuildError::*;
    use Term::*;
    let clos = |fs: &Vec<Term<Name, Name>>| {
        fs.iter()
            .map(|t: &Term<Name, Name>| {
                term_convert(spaces, temp_names, name_mapping, call_handles, known_state, t)
            })
            .collect::<Result<_, ProtoBuildError>>()
    };
    Ok(match term {
        True => True,
        False => False,
        Not(f) => Not(Box::new(term_convert(
            spaces,
            temp_names,
            name_mapping,
            call_handles,
            known_state,
            f,
        )?)),
        BoolCall { func, args } => BoolCall {
            func: call_handles.get(func).ok_or(UndefinedFuncName { name: func })?.clone(),
            args: clos(args)?,
        },
        And(fs) => And(clos(fs)?),
        Or(fs) => Or(clos(fs)?),
        IsEq(tid, box [lhs, rhs]) => {
            let [t0, t1] = [
                term_eval_tid(spaces, temp_names, name_mapping, &lhs)?,
                term_eval_tid(spaces, temp_names, name_mapping, &rhs)?,
            ];
            if t0 != t1 || t0 != *tid {
                return Err(EqForDifferentTypes);
            }
            IsEq(
                *tid,
                Box::new([
                    term_convert(spaces, temp_names, name_mapping, call_handles, known_state, lhs)?,
                    term_convert(spaces, temp_names, name_mapping, call_handles, known_state, rhs)?,
                ]),
            )
        }
        Named(name) => Named({
            if known_state.get(name).copied() != Some(true) {
                return Err(ReadWithoutFullCertainty { name });
            }
            resolve_full(temp_names, name_mapping, name)?
        }),
    })
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum LocKind {
    PoPu,
    PoGe,
    Memo,
}

impl ProtoDef {
    pub fn build(&self, init: MemInitial) -> Result<ProtoHandle, (Option<usize>, ProtoBuildError)> {
        build_proto(self, init)
    }
}
pub fn build_proto(
    p: &ProtoDef,
    mut init: MemInitial,
) -> Result<ProtoHandle, (Option<usize>, ProtoBuildError)> {
    use ProtoBuildError::*;

    let mut spaces = vec![];
    let mut name_mapping = BidirMap::<Name, LocId>::new();
    let mut unclaimed: HashSet<LocId> = hashset! {};
    let mut port_info: HashMap<LocId, (bool, TypeInfo)> = hashmap! {};
    let mut allocator = Allocator::default();

    let mut persistent_loc_kinds = vec![];

    // consume all name defs, creating spaces. retain call_handles to be treated later
    let mut mem: BitSet = Default::default();
    let mut ready = mem.clone();
    let mut call_handles: HashMap<Name, CallHandle> = hashmap! {};
    let mut ref_counts = hashmap!{};
    for (name, def) in p.name_defs.iter() {
        let id = LocId(spaces.len());
        name_mapping.insert(name, id);
        let (space, kind) = match def {
            NameDef::Port { is_putter, type_info } => {
                unclaimed.insert(id);
                port_info.insert(id, (*is_putter, *type_info));
                let mb = MsgBox::default();
                if *is_putter {
                    let ps = PutterSpace::new(std::ptr::null_mut(), *type_info);
                    (Space::PoPu { ps, mb }, LocKind::PoPu)
                } else {
                    (Space::PoGe { mb }, LocKind::PoGe)
                }
            }
            NameDef::Mem(type_info) => {
                ready.insert(id);
                let ptr = if let Some(bx) = init.strg.remove(name) {
                    let bx: Box<dyn PortDatum> = bx; // for readability
                    let (data, info) = trait_obj_read(&bx);
                    if info != *type_info {
                        return Err((None, InitialTypeMismatch { name }));
                    }
                    assert!(allocator.store(bx));
                    ref_counts.insert(data as usize, 1usize);
                    mem.insert(id);
                    data
                } else {
                    std::ptr::null_mut()
                };
                // putter space gets a copy too, not owned
                (Space::Memo { ps: PutterSpace::new(ptr, *type_info) }, LocKind::Memo)
            }
            NameDef::Func(call_handle) => {
                call_handles.insert(name, call_handle.clone());
                continue;
            }
        };
        spaces.push(space);
        persistent_loc_kinds.push(kind);
    }
    let perm_space_rng = 0..spaces.len();
    mem.pad_to_cap(perm_space_rng.end);
    ready.pad_to_cap(perm_space_rng.end);

    // NO MORE PERSISTENT THINGS
    let persistent_kind =
        |name: Name| Some(persistent_loc_kinds[name_mapping.get_by_first(&name)?.0]);

    // temp vars
    let mut temp_names: HashMap<Name, (LocId, TypeInfo)> = hashmap! {};
    let mut puts: HashSet<Name> = hashset! {};
    let mut gets: HashSet<Name> = hashset! {};
    let mut known_state: HashMap<Name, bool> = hashmap! {};

    // keeps track of PERM memory position for the purpose of matching the MOVEMENT to it (for changing assign bits)
    // key is location of mem (corresponding to the MOVEMENT PUTTER ultimately)
    // value is the permanent memcell where it started
    let mut whose_mem_is_this: HashMap<LocId, LocId> = hashmap!{}; 

    let mut rule_f = |rule: &RuleDef| {
        puts.clear();
        gets.clear();
        temp_names.clear();
        known_state.clear();
        whose_mem_is_this.clear();

        let StatePredicate { ready_ports, full_mem, empty_mem } = &rule.state_guard;
        // 1 ensure no conflicting mem requirements
        if let Some(name) = full_mem.intersection(empty_mem).next() {
            return Err(ConflictingMemPremise { name });
        }

        // 2 ensure no ports in mem position
        for name in full_mem.union(empty_mem) {
            if persistent_kind(name).ok_or(UndefinedLocName { name })? != LocKind::Memo {
                return Err(PortInMemPremise { name });
            }

        }

        let resolve =
            |name: &Name| name_mapping.get_by_first(name).copied().ok_or(UndefinedLocName { name });
        for name in ready_ports.iter() {
            let kind = persistent_kind(name).ok_or(UndefinedLocName { name })?;
            match kind {
                LocKind::PoPu => known_state.insert(name, true),
                LocKind::PoGe => known_state.insert(name, false),
                LocKind::Memo => return Err(MemInPortPremise { name }),
            };
        }

        // 6 store known state of memcells
        for name in full_mem.iter().copied() {
            known_state.insert(name, true);
        }
        for name in empty_mem.iter().copied() {
            known_state.insert(name, false);
        }

        // 5 build the bit guard
        let bit_guard = {
            let mut bit_guard: BitStatePredicate<BitSet> = BitStatePredicate {
                ready: ready_ports
                    .iter()
                    .chain(full_mem.iter())
                    .chain(empty_mem.iter())
                    .map(resolve)
                    .collect::<Result<_, _>>()?,
                full_mem: full_mem.iter().map(resolve).collect::<Result<_, _>>()?,
                empty_mem: empty_mem.iter().map(resolve).collect::<Result<_, _>>()?,
            };
            bit_guard.ready.pad_to_cap(perm_space_rng.end);
            bit_guard.full_mem.pad_to_cap(perm_space_rng.end);
            bit_guard.empty_mem.pad_to_cap(perm_space_rng.end);
            bit_guard
        };

        // identity for all permanent memcells
        whose_mem_is_this.extend(bit_guard.full_mem.iter().chain(bit_guard.empty_mem.iter()).map(|id| (id,id)));

        let mut ins = SmallVec::new();
        'instructions: for i in rule.ins.iter() {
            use Instruction::*;
            let instruction = match i {
                Check { term } => {
                    if term_eval_tid(&spaces, &temp_names, &name_mapping, &term)?
                        != TypeInfo::of::<bool>()
                    {
                        return Err(CheckingNonBoolType);
                    }
                    Instruction::Check {
                        term: term_convert(
                            &spaces,
                            &temp_names,
                            &name_mapping,
                            &call_handles,
                            &known_state,
                            term,
                        )?,
                    }
                }
                CreateFromFormula { dest, term } => {
                    let type_info = term_eval_tid(&spaces, &temp_names, &name_mapping, &term)?;
                    if type_info != TypeInfo::of::<bool>() {
                        return Err(CreatingNonBoolFromFormula);
                    }
                    if resolve_full(&temp_names, &name_mapping, dest).is_ok() {
                        return Err(InstructionCannotOverwrite { name: dest });
                    }
                    let ps = PutterSpace::new(std::ptr::null_mut(), type_info);
                    spaces.push(Space::Memo { ps });
                    let temp_id = LocId(spaces.len() - 1);
                    if temp_names.insert(dest, (temp_id, type_info)).is_some() {
                        return Err(InstructionShadowsName { name: dest });
                    }
                    let term = term_convert(
                        &spaces,
                        &temp_names,
                        &name_mapping,
                        &call_handles,
                        &known_state,
                        &term,
                    )?;
                    known_state.insert(dest, true); // must be a fresh name
                    CreateFromFormula { dest: temp_id, term }
                }
                CreateFromCall { info, dest, func, args } => {
                    let ch =
                        call_handles.get(func).ok_or(UndefinedFuncName { name: func })?.clone();
                    let args = args
                        .into_iter()
                        .map(|arg| {
                            term_convert(
                                &spaces,
                                &temp_names,
                                &name_mapping,
                                &call_handles,
                                &known_state,
                                arg,
                            )
                        })
                        .collect::<Result<Vec<_>, ProtoBuildError>>()?;
                    let temp_id = LocId(spaces.len());
                    let ps = PutterSpace::new(std::ptr::null_mut(), *info);
                    spaces.push(Space::Memo { ps });
                    if temp_names.insert(dest, (temp_id, *info)).is_some() {
                        return Err(InstructionShadowsName { name: dest });
                    }
                    known_state.insert(dest, true); // must be a fresh name
                    CreateFromCall { info: *info, dest: temp_id, func: ch.clone(), args }
                }
                MemSwap(a, b)=> {
                    let aid = resolve_full(&temp_names, &name_mapping, a);
                    let bid = resolve_full(&temp_names, &name_mapping, b);

                    let [aid, bid] = if aid.is_err() && bid.is_err() {
                        // swap of nothing to nothing
                        continue 'instructions;
                    } else if aid.is_err() || bid.is_err() {
                        // swap from existing to new temp
                        let (new_name, ex_name, ex_id) =
                            if aid.is_err() { (a, b, bid.unwrap()) } else { (b, a, aid.unwrap()) };
                        if let Space::Memo { ps } = &spaces[ex_id.0] {
                            let info = ps.type_info;
                            let temp_id = LocId(spaces.len());
                            temp_names.insert(new_name, (temp_id, info)); // cannot fail
                            spaces.push(Space::Memo {
                                ps: PutterSpace::new(std::ptr::null_mut(), info),
                            });
                            if let Some(x) = known_state.remove(ex_name) {
                                known_state.insert(new_name, x);
                            }
                            known_state.insert(ex_name, false);
                            [ex_id, temp_id]
                        } else {
                            return Err(CanOnlySwapMemory { name: ex_name });
                        }
                    } else {
                        // swap between existing
                        let ka = known_state.remove(a);
                        let kb = known_state.remove(b);
                        if let Some(x) = ka {
                            known_state.insert(b, x);
                        }
                        if let Some(x) = kb {
                            known_state.insert(a, x);
                        }
                        [aid.unwrap(), bid.unwrap()]
                    };
                    let wmit_a = whose_mem_is_this.remove(&aid);
                    let wmit_b = whose_mem_is_this.remove(&aid);
                    if let Some(x) = wmit_a {
                        whose_mem_is_this.insert(bid, x);
                    }
                    if let Some(x) = wmit_b {
                        whose_mem_is_this.insert(aid, x);
                    }
                    MemSwap(aid, bid)
                }
            };
            ins.push(instruction);
        }

        //DeBUGGY:println!("WHOSE {:?}", &whose_mem_is_this);

        let mut bit_assign = BitStatePredicate {
            ready: (), // always identical to bit_guard.ready. use that instead
            empty_mem: Default::default(),
            full_mem: Default::default(),
        };
        //DeBUGGY:println!("KS BEFORE {:?}", &known_state);
        let mut output: SmallVec<[Movement;4]> = rule
            .output
            .iter()
            .map(|(&putter, (putter_retains, getters))| {
                if known_state.get(putter).copied() != Some(true) {
                    return Err(PutWithoutFullCertainty { name: putter });
                }
                let putter_id: LocId = resolve_full(&temp_names, &name_mapping, putter)?;
                puts.insert(putter); // no overwrite possible
                let putter_type_info =
                    spaces[putter_id.0].get_putter_space().expect("CCC").type_info;
                if !putter_retains {
                    if let Some(x) = whose_mem_is_this.remove(&putter_id) {
                        bit_assign.empty_mem.insert(x);
                    }
                }
                let mut po_ge = vec![];
                let mut me_ge = vec![];
                for name in getters {
                    if known_state.get(name).copied() != Some(false) {
                        return Err(GetWithoutEmptyCertainty { name });
                    }
                    let gid = name_mapping.get_by_first(name).expect("DDD");
                    match persistent_loc_kinds[gid.0] {
                        LocKind::PoPu => return Err(PutterCannotGet { name }),
                        LocKind::PoGe => {
                            if !gets.insert(name) {
                                return Err(GetterHasMuliplePutters { name });
                            }
                            if port_info.get(gid).expect("EE").1 != putter_type_info {
                                return Err(MovementTypeMismatch { putter, getter: name });
                            }
                            &mut po_ge
                        }
                        LocKind::Memo => {
                            if spaces[gid.0].get_putter_space().expect("FFF").type_info
                                != putter_type_info
                            {
                                return Err(MovementTypeMismatch { putter, getter: name });
                            }
                            if let Some(x) = whose_mem_is_this.remove(&gid) {
                                bit_assign.full_mem.insert(x);
                            }
                            &mut me_ge
                        }
                    }
                    .push(*gid);
                }
                Ok(Movement { putter: putter_id, po_ge, me_ge, putter_retains: *putter_retains })
            })
            .collect::<Result<_, ProtoBuildError>>()?;
        //DeBUGGY:println!("KS AFTER {:?}. P|G: {:?}", &known_state, (&puts, &gets));
        for (name, is_full) in known_state.drain() {
            if puts.contains(name) || gets.contains(name) {
                continue; // ok it was covered
            }
            let id = resolve_full(&temp_names, &name_mapping, name)?;
            let putter_retains = match spaces[id.0] {
                Space::Memo{..} => perm_space_rng.contains(&id.0),
                Space::PoPu{..} => true,
                Space::PoGe{..} => return Err(GetterHasNoPutters { name }),
            };
            if is_full {
                output.push(Movement {
                    putter: id,
                    po_ge: vec![],
                    me_ge: vec![],
                    putter_retains,
                });
            }
        }
        bit_assign.full_mem.pad_to_cap(perm_space_rng.end);
        bit_assign.empty_mem.pad_to_cap(perm_space_rng.end);
        Ok(Rule { bit_guard, ins, output, bit_assign })
    };

    let rules = p
        .rules
        .iter()
        .enumerate()
        .map(|(rule_id, rule_def)| rule_f(rule_def).map_err(|e| (Some(rule_id), e)))
        .collect::<Result<_, (_, ProtoBuildError)>>()?;
    let r = ProtoR { rules, spaces, name_mapping, port_info, perm_space_rng,  };
    //DeBUGGY:println!("PROTO R {:#?}", &r);
    let cr = ProtoCr { unclaimed, allocator, mem, ready, ref_counts };
    r.sanity_check(&cr); // DEBUG
    Ok(ProtoHandle(Arc::new(Proto {
        r,
        cr: Mutex::new(cr),
    })))
}
