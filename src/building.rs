use super::*;

pub enum MemDef {
    Initialized(Box<dyn PortDatum>),
    Uninitialized(TypeInfo),
}
impl std::fmt::Debug for MemDef {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MemDef::Initialized(d) => write!(f, "Init({:?})", unsafe { trait_obj_read(d) }),
            MemDef::Uninitialized(t) => write!(f, "Uninit({:?})", t),
        }
    }
}
#[derive(Debug)]
pub enum NameDef {
    Port { is_putter: bool, type_info: TypeInfo },
    Mem(MemDef),
    Func(CallHandle),
}

#[derive(Debug)]
pub struct ProtoDef {
    pub name_defs: HashMap<Name, NameDef>,
    pub rules: Vec<RuleDef>,
}

#[derive(Debug)]
pub struct RulePremise {
    pub ready_ports: HashSet<Name>,
    pub full_mem: HashSet<Name>,
    pub empty_mem: HashSet<Name>,
}
#[derive(Debug)]
pub struct RuleDef {
    pub premise: RulePremise,
    pub ins: Vec<Instruction<Name, Name>>,
    pub output: HashMap<Name, (bool, HashSet<Name>)>,
}
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
    term: &Term<Name>,
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

fn term_eval_loc_id(
    spaces: &Vec<Space>,
    temp_names: &HashMap<Name, (LocId, TypeInfo)>,
    name_mapping: &BidirMap<Name, LocId>,
    term: Term<Name>,
) -> Result<Term<LocId>, ProtoBuildError> {
    use ProtoBuildError::*;
    use Term::*;
    let clos = |fs: Vec<Term<Name>>| {
        fs.into_iter()
            .map(|t: Term<Name>| term_eval_loc_id(spaces, temp_names, name_mapping, t))
            .collect::<Result<_, ProtoBuildError>>()
    };
    Ok(match term {
        True => True,
        False => False,
        Not(f) => Not(Box::new(term_eval_loc_id(
            spaces,
            temp_names,
            name_mapping,
            *f,
        )?)),
        And(fs) => And(clos(fs)?),
        Or(fs) => Or(clos(fs)?),
        IsEq(tid, box [lhs, rhs]) => {
            let [t0, t1] = [
                term_eval_tid(spaces, temp_names, name_mapping, &lhs)?,
                term_eval_tid(spaces, temp_names, name_mapping, &rhs)?,
            ];
            if t0 != t1 || t0 != tid {
                return Err(EqForDifferentTypes);
            }
            IsEq(
                tid,
                Box::new([
                    term_eval_loc_id(spaces, temp_names, name_mapping, lhs)?,
                    term_eval_loc_id(spaces, temp_names, name_mapping, rhs)?,
                ]),
            )
        }
        Named(name) => Named(resolve_putter(temp_names, name_mapping, name)?),
    })
}

pub fn build_proto(p: ProtoDef) -> Result<Proto, (usize, ProtoBuildError)> {
    use ProtoBuildError::*;

    let mut spaces = vec![];
    let mut name_mapping = BidirMap::<Name, LocId>::new();
    let mut unclaimed = hashmap! {};
    let mut allocator = Allocator::default();

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    enum LocKind {
        PoPu,
        PoGe,
        Memo,
    };

    let mut persistent_loc_kinds = vec![];

    // consume all name defs, creating spaces. retain call_handles to be treated later
    let call_handles: HashMap<Name, Arc<CallHandle>> = p
        .name_defs
        .into_iter()
        .filter_map(|(name, def)| {
            let id = LocId(spaces.len());
            name_mapping.insert(name, id);
            let (space, kind) = match def {
                NameDef::Port { is_putter, type_info } => {
                    unclaimed.insert(id, (is_putter, type_info));
                    let msgbox = MsgBox;
                    if is_putter {
                        let ps = PutterSpace::new(std::ptr::null_mut(), type_info);
                        (Space::PoPu(ps, msgbox), LocKind::PoPu)
                    } else {
                        (Space::PoGe(msgbox), LocKind::PoGe)
                    }
                }
                NameDef::Mem(mem_def) => {
                    let (ptr, info) = match mem_def {
                        MemDef::Initialized(bx) => unsafe {
                            let (data, info) = trait_obj_read(&bx);
                            allocator.store(bx);
                            (data, info)
                        },
                        MemDef::Uninitialized(info) => (std::ptr::null_mut(), info),
                    };
                    // putter space gets a copy too, not owned
                    (Space::Memo(PutterSpace::new(ptr, info)), LocKind::Memo)
                }
                NameDef::Func(call_handle) => return Some((name, Arc::new(call_handle))),
            };
            spaces.push(space);
            persistent_loc_kinds.push(kind);
            None
        })
        .collect();

    // temp vars
    let mut temp_names: HashMap<Name, (LocId, TypeInfo)> = hashmap! {};
    let mut rule_putters: HashSet<Name> = hashset! {};

    let mut rule_f = |rule: RuleDef| {
        rule_putters.clear();
        temp_names.clear();

        let RulePremise {
            ready_ports,
            full_mem,
            empty_mem,
        } = rule.premise;

        rule_putters.extend(
            ready_ports
                .iter()
                .filter(|&name| {
                    persistent_loc_kinds[name_mapping.get_by_first(name).unwrap().0]
                        == LocKind::PoPu
                })
                .chain(full_mem.iter())
                .copied(),
        );

        let map_id = |name, should_be_port| {
            let id = name_mapping
                .get_by_first(&name)
                .copied()
                .ok_or(UndefinedLocName { name })?;
            let is_port = persistent_loc_kinds[id.0] != LocKind::Memo;
            if is_port == should_be_port {
                Ok(id)
            } else if is_port {
                Err(PortInMemPremise { name })
            } else {
                Err(MemInPortPremise { name })
            }
        };
        let ready_ports: HashSet<LocId> = ready_ports
            .into_iter()
            .map(|x| map_id(x, true))
            .collect::<Result<_, ProtoBuildError>>()?;
        let full_mem: HashSet<LocId> = full_mem
            .into_iter()
            .map(|x| map_id(x, false))
            .collect::<Result<_, ProtoBuildError>>()?;
        let empty_mem = empty_mem
            .into_iter()
            .map(|x| map_id(x, false))
            .collect::<Result<_, ProtoBuildError>>()?;

        if let Some(id) = full_mem.intersection(&empty_mem).next() {
            return Err(ConflictingMemPremise {
                name: name_mapping.get_by_second(id).unwrap(),
            });
        }
        let RuleDef {
            ins, mut output, ..
        } = rule;
        let ins = ins
            .into_iter()
            .map(|i| {
                use Instruction::*;
                Ok(match i {
                    CreateFromFormula { dest, term } => {
                        let dest_id = resolve_putter(&temp_names, &name_mapping, dest)?;
                        let type_info = term_eval_tid(&spaces, &temp_names, &name_mapping, &term)?;
                        if type_info != TypeInfo::of::<bool>() {
                            return Err(CreatingNonBoolFromFormula);
                        }
                        if temp_names.insert(dest, (dest_id, type_info)).is_some() {
                            return Err(InstructionShadowsName { name: dest });
                        }
                        rule_putters.insert(dest);
                        let term = term_eval_loc_id(&spaces, &temp_names, &name_mapping, term)?;
                        CreateFromFormula {
                            dest: dest_id,
                            term,
                        }
                    }
                    CreateFromCall {
                        info,
                        dest,
                        func,
                        args,
                    } => {
                        let ch = call_handles
                            .get(func)
                            .ok_or(UndefinedFuncName { name: func })?
                            .clone();
                        let args = args
                            .into_iter()
                            .map(|arg| term_eval_loc_id(&spaces, &temp_names, &name_mapping, arg))
                            .collect::<Result<Vec<_>, ProtoBuildError>>()?;
                        let temp_id = LocId(spaces.len());
                        spaces.push(Space::Memo(PutterSpace::new(std::ptr::null_mut(), info)));
                        rule_putters.insert(dest);
                        if temp_names.insert(dest, (temp_id, info)).is_some() {
                            return Err(InstructionShadowsName { name: dest });
                        }
                        CreateFromCall {
                            info,
                            dest: temp_id,
                            func: ch,
                            args,
                        }
                    }
                    Check { term } => {
                        if term_eval_tid(&spaces, &temp_names, &name_mapping, &term)?
                            != TypeInfo::of::<bool>()
                        {
                            return Err(CheckingNonBoolType);
                        }
                        Check {
                            term: term_eval_loc_id(&spaces, &temp_names, &name_mapping, term)?,
                        }
                    }
                })
            })
            .collect::<Result<_, ProtoBuildError>>()?;
        println!("temp names {:?}", &temp_names);

        let new_output = rule_putters
            .iter()
            .map(|putter| {
                let putter_id: LocId = resolve_putter(&temp_names, &name_mapping, putter)?;
                let putter = *putter;
                Ok(
                    if let Some((putter_retains, getters)) = output.remove(putter) {
                        let getters = getters
                            .iter()
                            .map(|g_name| {
                                let gid = name_mapping.get_by_first(g_name).unwrap();
                                if rule_putters.contains(g_name) {
                                    return Err(GettingAndPutting { name: g_name });
                                }
                                match persistent_loc_kinds[gid.0] {
                                    LocKind::PoPu => {
                                        return Err(PutterPortCannotGet { name: g_name })
                                    }
                                    LocKind::PoGe => {
                                        if !ready_ports.contains(gid) {
                                            return Err(PortNotInSyncSet { name: g_name });
                                        }
                                    }
                                    LocKind::Memo => {
                                        if !full_mem.contains(gid) {
                                            return Err(MemCannotGetWhileFull { name: g_name });
                                        }
                                    }
                                };
                                Ok(*gid)
                            })
                            .collect::<Result<_, _>>()?;
                        Movement {
                            putter: putter_id,
                            getters,
                            putter_retains,
                        }
                    } else {
                        Movement {
                            putter: putter_id,
                            getters: vec![],
                            putter_retains: true,
                        }
                    },
                )
            })
            .collect::<Result<_, _>>()?;
        if let Some((name, v)) = output.drain().next() {
            return Err(PortNotInSyncSet { name });
        }

        Ok(Rule {
            ready_ports,
            full_mem,
            empty_mem,
            ins,
            output: new_output,
        })
    };

    let rules = p
        .rules
        .into_iter()
        .enumerate()
        .map(|(rule_id, rule_def)| rule_f(rule_def).map_err(|e| (rule_id, e)))
        .collect::<Result<_, (usize, ProtoBuildError)>>()?;

    let mem = BitSet::default();
    let ready = BitSet::default();
    Ok(Proto {
        r: ProtoR {
            rules,
            spaces,
            name_mapping,
        },
        cr: Mutex::new(ProtoCr {
            unclaimed,
            allocator,
            mem,
            ready,
            ref_counts: hashmap! {},
        }),
    })
}
