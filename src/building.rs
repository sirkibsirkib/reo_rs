use super::*;

#[derive(Debug, Clone)]
pub enum NameDef {
    Port { is_putter: bool, type_key: TypeKey },
    Mem { type_key: TypeKey },
    Func(CallHandle),
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProtoDef {
    pub name_defs: HashMap<Name, NameDef>,
    pub rules: Vec<RuleDef>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct StatePredicate {
    pub ready_ports: HashSet<Name>,
    pub full_mem: HashSet<Name>,
    pub empty_mem: HashSet<Name>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct RuleDef {
    // precondition for firing
    pub state_guard: StatePredicate,
    pub ins: Vec<Instruction<Name, Name>>,
    pub output: HashMap<Name, (bool, HashSet<Name>)>,
}
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
    GetterHasMultiplePutters { name: Name },
    GetterHasNoPutters { name: Name },
    PortInMemPremise { name: Name },
    MemInPortPremise { name: Name },
    ConflictingMemPremise { name: Name },
    InstructionShadowsName { name: Name },
    CheckingNonBoolType,
    CreatingNonBoolFromFormula,
    InitialTypeMismatch { name: Name },
    UnknownInitial { name: Name },
    MovementTypeMismatch { getter: Name, putter: Name },
    InstructionCannotOverwrite { name: Name }, // todo get more sophisticated
    CanOnlySwapMemory { name: Name },
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum LocKind {
    PoPu,
    PoGe,
    Memo,
}
/////////////////////////////////////

fn resolve_fully(
    temp_names: &HashMap<Name, (SpaceIndex, TypeKey)>,
    name_mapping: &BidirMap<Name, SpaceIndex>,
    name: Name,
) -> Result<SpaceIndex, ProtoBuildError> {
    use ProtoBuildError::*;
    temp_names
        .get(&name)
        .map(|x| x.0)
        .or_else(|| name_mapping.get_by_first(&name).copied())
        .ok_or(UndefinedLocName { name })
}

fn term_eval_tid(
    type_map: &TypeMap,
    spaces: &Vec<Space>,
    temp_names: &HashMap<Name, (SpaceIndex, TypeKey)>,
    name_mapping: &BidirMap<Name, SpaceIndex>,
    term: &Term<Name, Name>,
) -> Result<TypeKey, ProtoBuildError> {
    use ProtoBuildError::*;
    use Term::*;
    Ok(match term {
        Named(name) => {
            spaces[resolve_fully(temp_names, name_mapping, name)?.0]
                .get_putter_space()
                .ok_or(TermNameIsNotPutter { name })?
                .type_key
        }
        _ => type_map.bool_type_key,
    })
}

fn term_convert(
    type_map: &TypeMap,
    spaces: &Vec<Space>,
    temp_names: &HashMap<Name, (SpaceIndex, TypeKey)>,
    name_mapping: &BidirMap<Name, SpaceIndex>,
    call_handles: &HashMap<Name, CallHandle>,
    known_state: &HashMap<Name, bool>,
    term: &Term<Name, Name>,
) -> Result<Term<SpaceIndex, CallHandle>, ProtoBuildError> {
    use ProtoBuildError::*;
    use Term::*;
    let clos = |fs: &Vec<Term<Name, Name>>| {
        fs.iter()
            .map(|t: &Term<Name, Name>| {
                term_convert(
                        type_map,spaces, temp_names, name_mapping, call_handles, known_state, t)
            })
            .collect::<Result<_, ProtoBuildError>>()
    };
    Ok(match term {
        True => True,
        False => False,
        Not(f) => Not(Box::new(term_convert(
                        type_map,
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
        IsEq(tid, boxed) => {
            let [lhs, rhs] = [&boxed[0], &boxed[1]];
            let [t0, t1] = [
                term_eval_tid(type_map, spaces, temp_names, name_mapping, &lhs)?,
                term_eval_tid(type_map,spaces, temp_names, name_mapping, &rhs)?,
            ];
            if t0 != t1 || t0 != *tid {
                return Err(EqForDifferentTypes);
            }
            IsEq(
                *tid,
                Box::new([
                    term_convert(type_map,spaces, temp_names, name_mapping, call_handles, known_state, lhs)?,
                    term_convert(type_map,spaces, temp_names, name_mapping, call_handles, known_state, rhs)?,
                ]),
            )
        }
        Named(name) => Named({
            if known_state.get(name).copied() != Some(true) {
                return Err(ReadWithoutFullCertainty { name });
            }
            resolve_fully(temp_names, name_mapping, name)?
        }),
    })
}

pub fn build_proto_protected(proto_def: &ProtoDef, type_map: TypeProtected<TypeMap>) -> Result<TypeProtected<ProtoHandle>, (Option<usize>, ProtoBuildError)> {
    build_proto(proto_def, Arc::new(type_map.0)).map(TypeProtected)
}


pub fn build_proto(proto_def: &ProtoDef, type_map: Arc<TypeMap>) -> Result<ProtoHandle, (Option<usize>, ProtoBuildError)> {
    use ProtoBuildError::*;

    let mut spaces = vec![];
    let mut name_mapping = BidirMap::<Name, SpaceIndex>::new();
    let mut unclaimed: HashSet<SpaceIndex> = hashset! {};
    // locid -> (is_putter, type_key)

    let mut port_type_key: HashMap<SpaceIndex, (bool, TypeKey)> = hashmap! {};

    let mut persistent_loc_kinds = vec![];

    // consume all name defs, creating spaces. retain call_handles to be treated later
    let mut ready = BitSet::default();
    let mut call_handles: HashMap<Name, CallHandle> = hashmap! {};
    for (name, def) in proto_def.name_defs.iter() {
        let id = SpaceIndex(spaces.len());
        name_mapping.insert(name, id);
        let (space, kind) = match def {
            NameDef::Port { is_putter, type_key } => {
                unclaimed.insert(id);
                port_type_key.insert(id, (*is_putter, *type_key));
                let mb = MsgBox::default();
                if *is_putter {
                    let ps = PutterSpace::new( *type_key);
                    (Space::PoPu { ps, mb }, LocKind::PoPu)
                } else {
                    (Space::PoGe { mb, type_key: *type_key }, LocKind::PoGe)
                }
            }
            NameDef::Mem { type_key } => {
                ready.insert(id);
                (Space::Memo { ps: PutterSpace::new( *type_key) }, LocKind::Memo)
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
    let mem = BitSet::padded_to_cap(perm_space_rng.end);
    ready.pad_to_cap(perm_space_rng.end);

    // NO MORE PERSISTENT THINGS
    let persistent_kind =
        |name: Name| Some(persistent_loc_kinds[name_mapping.get_by_first(&name)?.0]);

    // temp vars
    let mut temp_names: HashMap<Name, (SpaceIndex, TypeKey)> = hashmap! {};
    let mut puts: HashSet<Name> = hashset! {};
    let mut gets: HashSet<Name> = hashset! {};
    let mut known_state: HashMap<Name, bool> = hashmap! {};

    // keeps track of PERM memory position for the purpose of matching the MOVEMENT to it (for changing assign bits)
    // key is location of mem (corresponding to the MOVEMENT PUTTER ultimately)
    // value is the permanent memcell where it started
    let mut whose_mem_is_this: HashMap<SpaceIndex, SpaceIndex> = hashmap! {};

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
            let mut bit_guard: BitStatePredicate = BitStatePredicate {
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
        whose_mem_is_this
            .extend(bit_guard.full_mem.iter().chain(bit_guard.empty_mem.iter()).map(|id| (id, id)));

        let mut ins = SmallVec::new();
        let bool_type_key = type_map.bool_type_key;
        'instructions: for i in rule.ins.iter() {
            use Instruction::*;
            let instruction = match i {
                Check(term) => {
                    if term_eval_tid(&type_map,&spaces, &temp_names, &name_mapping, &term)?
                        != bool_type_key
                    {
                        return Err(CheckingNonBoolType);
                    }
                    Instruction::Check(term_convert(
                        &type_map,
                        &spaces,
                        &temp_names,
                        &name_mapping,
                        &call_handles,
                        &known_state,
                        term,
                    )?)
                }
                CreateFromFormula { dest, term } => {
                    let type_key = term_eval_tid(
                        &type_map,&spaces, &temp_names, &name_mapping, &term)?;
                    if type_key != bool_type_key {
                        return Err(CreatingNonBoolFromFormula);
                    }
                    if resolve_fully(&temp_names, &name_mapping, dest).is_ok() {
                        return Err(InstructionCannotOverwrite { name: dest });
                    }
                    let ps = PutterSpace::new( type_key);
                    spaces.push(Space::Memo { ps });
                    let temp_id = SpaceIndex(spaces.len() - 1);
                    if temp_names.insert(dest, (temp_id, type_key)).is_some() {
                        return Err(InstructionShadowsName { name: dest });
                    }
                    let term = term_convert(
                        &type_map,
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
                CreateFromCall { type_key, dest, func, args } => {
                    let ch =
                        call_handles.get(func).ok_or(UndefinedFuncName { name: func })?.clone();
                    let args = args
                        .into_iter()
                        .map(|arg| {
                            term_convert(
                        &type_map,
                                &spaces,
                                &temp_names,
                                &name_mapping,
                                &call_handles,
                                &known_state,
                                arg,
                            )
                        })
                        .collect::<Result<Vec<_>, ProtoBuildError>>()?;
                    let temp_id = SpaceIndex(spaces.len());
                    let ps = PutterSpace::new(*type_key);
                    spaces.push(Space::Memo { ps });
                    if temp_names.insert(dest, (temp_id, *type_key)).is_some() {
                        return Err(InstructionShadowsName { name: dest });
                    }
                    known_state.insert(dest, true); // must be a fresh name
                    CreateFromCall { type_key: *type_key, dest: temp_id, func: ch.clone(), args }
                }
                MemSwap(a, b) => {
                    let aid = resolve_fully(&temp_names, &name_mapping, a);
                    let bid = resolve_fully(&temp_names, &name_mapping, b);

                    let [aid, bid] = if aid.is_err() && bid.is_err() {
                        // swap of nothing to nothing
                        continue 'instructions;
                    } else if aid.is_err() || bid.is_err() {
                        // swap from existing to new temp
                        let (new_name, ex_name, ex_id) =
                            if aid.is_err() { (a, b, bid.unwrap()) } else { (b, a, aid.unwrap()) };
                        if let Space::Memo { ps } = &spaces[ex_id.0] {
                            let type_key = ps.type_key;
                            let temp_id = SpaceIndex(spaces.len());
                            temp_names.insert(new_name, (temp_id, type_key)); // cannot fail
                            spaces.push(Space::Memo {
                                ps: PutterSpace::new( type_key),
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
            ready: bit_guard.ready.clone(),
            empty_mem: Default::default(),
            full_mem: Default::default(),
        };
        //DeBUGGY:println!("KS BEFORE {:?}", &known_state);
        let mut output: SmallVec<[Movement; 4]> = rule
            .output
            .iter()
            .map(|(&putter, (putter_retains, getters))| {
                if known_state.get(putter).copied() != Some(true) {
                    return Err(PutWithoutFullCertainty { name: putter });
                }
                let putter_id: SpaceIndex = resolve_fully(&temp_names, &name_mapping, putter)?;
                puts.insert(putter); // no overwrite possible
                let putter_type_key =
                    spaces[putter_id.0].get_putter_space().expect("CCC").type_key;
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
                                return Err(GetterHasMultiplePutters { name });
                            }
                            if port_type_key.get(gid).expect("EE").1 != putter_type_key {
                                return Err(MovementTypeMismatch { putter, getter: name });
                            }
                            &mut po_ge
                        }
                        LocKind::Memo => {
                            if spaces[gid.0].get_putter_space().expect("FFF").type_key
                                != putter_type_key
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
            let id = resolve_fully(&temp_names, &name_mapping, name)?;
            let putter_retains = match spaces[id.0] {
                Space::Memo { .. } => perm_space_rng.contains(&id.0),
                Space::PoPu { .. } => true,
                Space::PoGe { .. } => return Err(GetterHasNoPutters { name }),
            };
            if is_full {
                output.push(Movement { putter: id, po_ge: vec![], me_ge: vec![], putter_retains });
            } else {
                // cover the case of an EMPTY movement. nobody drains it AND its not full
                bit_assign.ready.remove(&id);
            }
        }
        bit_assign.full_mem.pad_to_cap(perm_space_rng.end);
        bit_assign.empty_mem.pad_to_cap(perm_space_rng.end);
        Ok(Rule { bit_guard, ins, output, bit_assign })
    };

    let rules = proto_def
        .rules
        .iter()
        .enumerate()
        .map(|(rule_id, rule_def)| rule_f(rule_def).map_err(|e| (Some(rule_id), e)))
        .collect::<Result<_, (_, ProtoBuildError)>>()?;

    let allocator =  Allocator::new(type_map.clone());
    let r = ProtoR { type_map, rules, spaces, name_mapping, perm_space_rng };
    //DeBUGGY:println!("PROTO R {:#?}", &r);
    let cr = ProtoCr { unclaimed, allocator, mem, ready, ref_counts: hashmap!{} };
    r.sanity_check(&cr); // DEBUG
    Ok(ProtoHandle(Arc::new(Proto { r, cr: Mutex::new(cr) })))
}