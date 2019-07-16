use super::*;

#[derive(Default)]
pub struct MemInitial {
    strg: HashMap<Name, Box<dyn PortDatum>>,
}
impl MemInitial {
    #[inline]
    pub fn with<T: PubPortDatum>(mut self, name: Name, init: T) -> Self {
        let dy: Box<dyn PortDatum> = Box::new(init);
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

/*
an instruction starts with a premise which guarantees which port



*/

#[derive(Debug)]
pub enum ProtoBuildError {
    UnavailableData { name: Name, rule_index: usize },
    UndefinedLocName { name: Name },
    UndefinedFuncName { name: Name },
    DuplicateNameDef { name: Name },
    MemoryNotInitialized { name: Name },
    TermNameIsNotPutter { name: Name },
    EqForDifferentTypes,
    GetterHasMuliplePutters { name: Name },
    GetterHasNoPutters { name: Name },
    PortInMemPremise { name: Name },
    MemInPortPremise { name: Name },
    ConflictingMemPremise { name: Name },
    GettingAndPutting { name: Name },
    InstructionShadowsName { name: Name },
    PutterPortCannotGet { name: Name },
    PortNotInSyncSet { name: Name },
    MemCannotGetWhileFull { name: Name },
    CheckingNonBoolType,
    CreatingNonBoolFromFormula,
    InitialTypeMismatch { name: Name },
    PutterCannotPutWhenEmpty { name: Name },
    MovementTypeMismatch { getter: Name, putter: Name },
}

fn resolve_putter(
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
            spaces[resolve_putter(temp_names, name_mapping, name)?.0]
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
    term: &Term<Name, Name>,
) -> Result<Term<LocId, CallHandle>, ProtoBuildError> {
    use ProtoBuildError::*;
    use Term::*;
    let clos = |fs: &Vec<Term<Name, Name>>| {
        fs.iter()
            .map(|t: &Term<Name, Name>| {
                term_convert(spaces, temp_names, name_mapping, call_handles, t)
            })
            .collect::<Result<_, ProtoBuildError>>()
    };
    Ok(match term {
        True => True,
        False => False,
        Not(f) => Not(Box::new(term_convert(spaces, temp_names, name_mapping, call_handles, f)?)),
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
                    term_convert(spaces, temp_names, name_mapping, call_handles, lhs)?,
                    term_convert(spaces, temp_names, name_mapping, call_handles, rhs)?,
                ]),
            )
        }
        Named(name) => Named(resolve_putter(temp_names, name_mapping, name)?),
    })
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum LocKind {
    PoPu,
    PoGe,
    Memo,
}

// #[derive(Default)]
// struct ProtoBuilder {
//     spaces: Vec<Space>,
//     name_mapping: BidirMap::<Name, LocId>,
//     unclaimed: HashSet<LocId>,
//     port_info: HashMap<LocId, (bool, TypeInfo)>,
//     allocator: Allocator,
//     persistent_loc_kinds: Vec<LocKind>,
//     mem: HashSet<LocId>,
//     ready: HashSet<LocId>,
//     call_handles: HashMap<Name, CallHandle>,
// }
// impl ProtoBuilder  {
//     pub fn build_proto(
//         p: &ProtoDef,
//         mut init: MemInitial,
//     ) -> Result<ProtoHandle, (Option<usize>, ProtoBuildError)> {
//     }
// }

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
    let mut mem: HashSet<LocId> = hashset! {};
    let mut ready = mem.clone();
    let mut call_handles: HashMap<Name, CallHandle> = hashmap! {};
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
                    let (data, info) = unsafe { trait_obj_read(&bx) };
                    if info != *type_info {
                        return Err((None, InitialTypeMismatch { name }));
                    }
                    allocator.store(bx);
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

    // NO MORE PERSISTENT THINGS
    let persistent_kind =
        |name: Name| Some(persistent_loc_kinds[name_mapping.get_by_first(&name)?.0]);

    // temp vars
    let mut temp_names: HashMap<Name, (LocId, TypeInfo)> = hashmap! {};
    let mut to_put: HashSet<Name> = hashset! {};
    let mut outputting: HashSet<Name> = hashset! {};

    let mut rule_f = |rule: &RuleDef| {
        to_put.clear();
        temp_names.clear();

        let StatePredicate { ready_ports, full_mem, empty_mem } = &rule.state_guard;

        // keep track of which putters still must put their values
        for name in ready_ports.iter() {
            if persistent_kind(name).ok_or(UndefinedLocName { name })? == LocKind::PoPu {
                to_put.insert(name);
            }
        }
        to_put.extend(full_mem.iter().copied());

        // build guard BitStatePredicate
        let map_id = |name, should_be_port| {
            let id = name_mapping.get_by_first(&name).copied().ok_or(UndefinedLocName { name })?;
            let is_port = persistent_loc_kinds[id.0] != LocKind::Memo;
            if is_port == should_be_port {
                Ok(id)
            } else if is_port {
                Err(PortInMemPremise { name })
            } else {
                Err(MemInPortPremise { name })
            }
        };
        let bit_guard = {
            let full_mem: HashSet<LocId> = full_mem
                .into_iter()
                .map(|x| map_id(x, false))
                .collect::<Result<_, ProtoBuildError>>()?;
            let empty_mem: HashSet<LocId> = empty_mem
                .into_iter()
                .map(|x| map_id(x, false))
                .collect::<Result<_, ProtoBuildError>>()?;

            if let Some(id) = full_mem.intersection(&empty_mem).next() {
                return Err(ConflictingMemPremise {
                    name: name_mapping.get_by_second(id).expect("BBB"),
                });
            }

            let mut ready: HashSet<LocId> = ready_ports
                .into_iter()
                .map(|x| map_id(x, true))
                .collect::<Result<_, ProtoBuildError>>()?;
            ready.extend(full_mem.iter().copied());
            ready.extend(empty_mem.iter().copied());
            BitStatePredicate { ready, full_mem, empty_mem }
        };

        let ins = rule
            .ins
            .iter()
            .map(|i| {
                Ok(match i {
                    Instruction::Check { term } => {
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
                                term,
                            )?,
                        }
                    }
                    _ => unimplemented!(),
                })
            })
            .collect::<Result<Vec<_>, ProtoBuildError>>()?;

        // COMMITTED BELOW THIS LINE. to_put is FINAL
        // outputting is now fixed. lists all ids that are PUTTING (to check for conflict)
        outputting.extend(to_put.iter().copied());

        let mut bit_assign = BitStatePredicate {
            ready: (), // always identical to bit_guard.ready. use that instead
            empty_mem: hashset! {},
            full_mem: hashset! {},
        };
        let mut output: Vec<Movement> = rule
            .output
            .iter()
            .map(|(&putter, (putter_retains, getters))| {
                if !to_put.remove(putter) {
                    return Err(PutterCannotPutWhenEmpty { name: putter });
                }
                let putter_id: LocId = resolve_putter(&temp_names, &name_mapping, putter)?;
                let putter_type_info =
                    spaces[putter_id.0].get_putter_space().expect("CCC").type_info;
                let putter_kind: LocKind =
                    *persistent_loc_kinds.get(putter_id.0).unwrap_or(&LocKind::Memo);
                if !putter_retains && putter_kind == LocKind::Memo {
                    bit_assign.empty_mem.insert(putter_id);
                }
                let mut po_ge = vec![];
                let mut me_ge = vec![];
                for name in getters {
                    let gid = name_mapping.get_by_first(name).expect("DDD");
                    if outputting.contains(name) {
                        return Err(GettingAndPutting { name });
                    }
                    match persistent_loc_kinds[gid.0] {
                        LocKind::PoPu => return Err(PutterPortCannotGet { name }),
                        LocKind::PoGe => {
                            if port_info.get(gid).expect("EE").1 != putter_type_info {
                                return Err(MovementTypeMismatch { putter, getter: name });
                            }
                            if !bit_guard.ready.contains(gid) {
                                return Err(PortNotInSyncSet { name });
                            }
                            &mut po_ge
                        }
                        LocKind::Memo => {
                            if spaces[gid.0].get_putter_space().expect("FFF").type_info
                                != putter_type_info
                            {
                                return Err(MovementTypeMismatch { putter, getter: name });
                            }
                            if !bit_guard.empty_mem.contains(gid) {
                                return Err(MemCannotGetWhileFull { name });
                            }
                            bit_assign.full_mem.insert(*gid);
                            &mut me_ge
                        }
                    }
                    .push(*gid);
                }
                Ok(Movement { putter: putter_id, po_ge, me_ge, putter_retains: *putter_retains })
            })
            .collect::<Result<_, ProtoBuildError>>()?;
        for putter in to_put.drain() {
            output.push(Movement {
                putter: resolve_putter(&temp_names, &name_mapping, putter)?,
                po_ge: vec![],
                me_ge: vec![],
                putter_retains: true,
            })
        }

        Ok(Rule { bit_guard, ins, output, bit_assign })
    };

    let rules = p
        .rules
        .iter()
        .enumerate()
        .map(|(rule_id, rule_def)| rule_f(rule_def).map_err(|e| (Some(rule_id), e)))
        .collect::<Result<_, (_, ProtoBuildError)>>()?;
    let r = ProtoR { rules, spaces, name_mapping, port_info };
    println!("PROTO R {:#?}", &r);
    r.sanity_check(); // DEBUG
    Ok(ProtoHandle(Arc::new(Proto {
        r,
        cr: Mutex::new(ProtoCr { unclaimed, allocator, mem, ready, ref_counts: hashmap! {} }),
    })))
}

// let ins = ins
//     .iter()
//     .map(|i| {
//         use Instruction::*;
//         Ok(match i {
//             MemMove { src, dest } => {
//                 unimplemented!()
//             }
//             CreateFromFormula { dest, term } => {
//                 let dest_id = resolve_putter(&temp_names, &name_mapping, dest)?;
//                 let type_info = term_eval_tid(&spaces, &temp_names, &name_mapping, &term)?;
//                 if type_info != TypeInfo::of::<bool>() {
//                     return Err(CreatingNonBoolFromFormula);
//                 }
//                 let ps = PutterSpace::new(std::ptr::null_mut(), type_info);
//                 spaces.push(Space::Memo { ps });
//                 if temp_names.insert(dest, (dest_id, type_info)).is_some() {
//                     return Err(InstructionShadowsName { name: dest });
//                 }
//                 rule_putters.insert(dest);
//                 let term = term_convert(&spaces, &temp_names, &name_mapping, &term)?;
//                 CreateFromFormula {
//                     dest: dest_id,
//                     term,
//                 }
//             }
//             CreateFromCall {
//                 info,
//                 dest,
//                 func,
//                 args,
//             } => {
//                 let ch = call_handles
//                     .get(func)
//                     .ok_or(UndefinedFuncName { name: func })?
//                     .clone();
//                 let args = args
//                     .into_iter()
//                     .map(|arg| term_convert(&spaces, &temp_names, &name_mapping, arg))
//                     .collect::<Result<Vec<_>, ProtoBuildError>>()?;
//                 let temp_id = LocId(spaces.len());
//                 let ps = PutterSpace::new(std::ptr::null_mut(), *info);
//                 spaces.push(Space::Memo { ps });
//                 rule_putters.insert(dest);
//                 if temp_names.insert(dest, (temp_id, *info)).is_some() {
//                     return Err(InstructionShadowsName { name: dest });
//                 }
//                 CreateFromCall {
//                     info: *info,
//                     dest: temp_id,
//                     func: ch.clone(),
//                     args,
//                 }
//             }
//             Check { term } => {
//                 if term_eval_tid(&spaces, &temp_names, &name_mapping, &term)?
//                     != TypeInfo::of::<bool>()
//                 {
//                     return Err(CheckingNonBoolType);
//                 }
//                 Check {
//                     term: term_convert(&spaces, &temp_names, &name_mapping, term)?,
//                 }
//             }
//         })
//     })
//     .collect::<Result<_, ProtoBuildError>>()?;
