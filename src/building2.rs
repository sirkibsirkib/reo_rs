use crate::*;

pub struct ProtoDef {
    pub mover_defs: Vec<MoverDef>,
    pub rules: Vec<RuleDef>,
}

#[derive(Default)]
struct ReadyKindSubsets {
    putter_ports: IndexSet<2>,
    getter_ports: IndexSet<2>,
    memory_cells: IndexSet<2>,
}

pub struct RuleDef {
    pub ready: IndexSet<2>,
    pub ready_and_full_mem: IndexSet<2>,
    pub instructions: Vec<Instruction>,
    pub movements: Vec<Movement>,
}

pub struct Movement {
    pub putter: Index,
    pub putter_retains: bool,
    pub getters: IndexSet<2>,
}

#[derive(Debug, Copy, Clone)]
pub struct MoverDef {
    pub type_key: TypeKey,
    pub mover_kind: MoverKind,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MoverKind {
    PutterPort,
    GetterPort,
    MemoryCell,
}

#[derive(Debug, Clone)]
pub struct RulesBuildError {
    rule_index: usize,
    rule_build_error: RuleBuildError,
}
#[derive(Debug, Clone)]
pub enum RuleBuildError {
    MoverUnready(Index),
    IndexOutOfBounds(Index),
    MoverCannotPut(Index),
    MoverCannotGet(Index),
    MoverisntMemory(Index),
    TypeInequality(TypeKey, TypeKey),
    ReadingUnfilled(Index),
    Overwriting(Index),
    FuncHasWrongArgNumber { func_has: usize, other_has: usize },
    NotUniqueInMovements(Index),
    MoverTypeMissingClone(Index),
    ReadyButDoesntMove(Index),
}

trait MoverReadyChecker {
    fn unready(&self, ready: &IndexSet<2>) -> Option<Index>;
}
impl MoverDef {
    fn to_space(self) -> MoverSpace {
        let Self { type_key, mover_kind } = self;

        match self.mover_kind {
            MoverKind::PutterPort => {
                MoverSpace::PoPu { mb: Default::default(), ps: PutterSpace::new(type_key) }
            }
            MoverKind::GetterPort => MoverSpace::PoGe { mb: Default::default(), type_key },
            MoverKind::MemoryCell => MoverSpace::Memo { ps: PutterSpace::new(type_key) },
        }
    }
}

impl ProtoDef {
    fn memory_mover_indices(&self) -> IndexSet<2> {
        self.mover_defs
            .iter()
            .enumerate()
            .filter_map(|(i, mover_def)| match mover_def.mover_kind {
                MoverKind::MemoryCell => Some(i),
                _ => None,
            })
            .collect()
    }
    fn port_mover_indices(&self) -> IndexSet<2> {
        self.mover_defs
            .iter()
            .enumerate()
            .filter_map(|(i, mover_def)| match mover_def.mover_kind {
                MoverKind::MemoryCell => None,
                _ => Some(i),
            })
            .collect()
    }
    fn build_rules(&self) -> Result<Vec<Rule>, RulesBuildError> {
        self.rules
            .iter()
            .enumerate()
            .map(|(rule_index, rule)| {
                build_rule(&self.mover_defs, rule)
                    .map_err(|rule_build_error| RulesBuildError { rule_index, rule_build_error })
            })
            .collect()
    }
    pub fn build(&self) -> Result<Proto, RulesBuildError> {
        Ok(Proto {
            r: ProtoR {
                rules: self.build_rules()?,
                spaces: self.mover_defs.iter().copied().map(MoverDef::to_space).collect(),
            },
            cr: Mutex::new(ProtoCr {
                allocator: Default::default(),
                mem_filled: Default::default(),
                ready: self.memory_mover_indices(),
                ref_counts: Default::default(),
                unclaimed: self.port_mover_indices(),
            }),
        })
    }
}

fn in_term_out_set(set: &IndexSet<2>, term: &Term) -> Option<Index> {
    match term {
        Term::True | Term::False => None,
        Term::Not(inner_term) => in_term_out_set(set, inner_term),
        Term::And(terms) | Term::Or(terms) => {
            terms.iter().find_map(|term| in_term_out_set(set, term))
        }
        Term::IsEq(_type_key, term_pair) => {
            term_pair.iter().find_map(|term| in_term_out_set(set, term))
        }
        Term::Named(mover_index) => {
            if set.contains(*mover_index) {
                None
            } else {
                Some(*mover_index)
            }
        }
    }
}
fn in_term_in_set(set: &IndexSet<2>, term: &Term) -> Option<Index> {
    match term {
        Term::True | Term::False => None,
        Term::Not(inner_term) => in_term_in_set(set, inner_term),
        Term::And(terms) | Term::Or(terms) => {
            terms.iter().find_map(|term| in_term_in_set(set, term))
        }
        Term::IsEq(_type_key, term_pair) => {
            term_pair.iter().find_map(|term| in_term_in_set(set, term))
        }
        Term::Named(mover_index) => {
            if set.contains(*mover_index) {
                Some(*mover_index)
            } else {
                None
            }
        }
    }
}

fn build_rule(mover_defs: &Vec<MoverDef>, rule_def: &RuleDef) -> Result<Rule, RuleBuildError> {
    use RuleBuildError as Rbe;

    // check that ready -> defined
    match rule_def.ready.max_element() {
        Some(max) if mover_defs.len() <= max => return Err(Rbe::IndexOutOfBounds(max)),
        _ => {}
    }

    // check that in ruledef -> ready
    if let Some(mover_index) = rule_def.unready(&rule_def.ready) {
        return Err(Rbe::MoverUnready(mover_index));
    }

    // in ruledef -> ready and defined

    let rks = {
        let mut rks = ReadyKindSubsets::default();
        for i in rule_def.ready.iter() {
            match mover_defs[i].mover_kind {
                MoverKind::PutterPort => &mut rks.putter_ports,
                MoverKind::GetterPort => &mut rks.getter_ports,
                MoverKind::MemoryCell => &mut rks.memory_cells,
            }
            .insert(i);
        }
        rks
    };

    // let's walk over instructions. check that we read only filled, write only unfilled, and that types match everywhere
    let mut filled: IndexSet<2> = rule_def.ready_and_full_mem.or(&rks.putter_ports).to_index_set();

    println!("{:?} filled", &filled);
    for ins in rule_def.instructions.iter() {
        println!("{:?} filled_before", &filled);
        instruction_fill(mover_defs, &mut filled, ins)?;
    }
    rule_movements(mover_defs, &mut filled, rule_def)?;

    /////////////////////////////////////////////////////
    // OK!

    let bit_guard = BitStatePredicate {
        ready: rule_def.ready.clone(),
        full_mem: rule_def.ready_and_full_mem.clone(),
        empty_mem: rks.memory_cells.without(&rule_def.ready_and_full_mem).to_index_set(),
    };
    // now we create the movements
    let output: SmallVec<[PartitionedMovement; 3]> = rule_def
        .movements
        .iter()
        .map(|movement| PartitionedMovement {
            putter: movement.putter,
            putter_retains: movement.putter_retains,
            me_ge: movement.getters.without(&rks.getter_ports).to_index_set(),
            po_ge: movement.getters.without(&rks.memory_cells).to_index_set(),
        })
        .collect();

    let rule = Rule {
        bit_guard,
        ins: rule_def.instructions.iter().cloned().collect(),
        output,
        make_mems_filled: rks
            .memory_cells
            .and(&filled)
            .without(&rule_def.ready_and_full_mem)
            .to_index_set(),
        make_mems_empty: rks.memory_cells.without(&filled).to_index_set(),
    };
    println!("rule {:#?}", &rule);
    Ok(rule)
}

///////////////////////
// THE FOLLOWING ALL ASSUME READY. READY -> DEFINED

fn mover_def(mover_defs: &Vec<MoverDef>, mover_index: Index) -> MoverDef {
    mover_defs[mover_index]
}

fn mover_type(mover_defs: &Vec<MoverDef>, mover_index: Index) -> TypeKey {
    mover_def(mover_defs, mover_index).type_key
}

fn mover_kind(mover_defs: &Vec<MoverDef>, mover_index: Index) -> MoverKind {
    mover_def(mover_defs, mover_index).mover_kind
}

fn term_type(mover_defs: &Vec<MoverDef>, term: &Term) -> TypeKey {
    match term {
        Term::Named(mover_index) => mover_type(mover_defs, *mover_index),
        _ => BOOL_TYPE_KEY,
    }
}

fn first_unready(ready: &IndexSet<2>, i: impl IntoIterator<Item = Index>) -> Option<Index> {
    i.into_iter().find_map(|x| x.unready(ready))
}

impl MoverReadyChecker for Index {
    fn unready(&self, ready: &IndexSet<2>) -> Option<Index> {
        if ready.contains(*self) {
            None
        } else {
            Some(*self)
        }
    }
}

impl MoverReadyChecker for Term {
    fn unready(&self, ready: &IndexSet<2>) -> Option<Index> {
        in_term_out_set(ready, self)
    }
}

impl MoverReadyChecker for Instruction {
    fn unready(&self, ready: &IndexSet<2>) -> Option<Index> {
        match self {
            Instruction::CreateFromFormula { dest, term } => {
                dest.unready(ready).or(term.unready(ready))
            }
            Instruction::CreateFromCall { dest, func: _, args } => {
                dest.unready(ready).or(args.iter().find_map(|ins| ins.unready(ready)))
            }
            Instruction::Check(term) => term.unready(ready),
            Instruction::MemSwap(a, b) => first_unready(ready, [*a, *b].iter().copied()),
        }
    }
}

impl MoverReadyChecker for RuleDef {
    fn unready(&self, ready: &IndexSet<2>) -> Option<Index> {
        first_unready(ready, self.ready_and_full_mem.iter())
            .or(self.instructions.iter().find_map(|ins| ins.unready(ready)))
    }
}

fn instruction_fill(
    mover_defs: &Vec<MoverDef>,
    filled: &mut IndexSet<2>,
    ins: &Instruction,
) -> Result<(), RuleBuildError> {
    use RuleBuildError as Rbe;
    match ins {
        Instruction::CreateFromFormula { dest, term } => {
            if mover_kind(mover_defs, *dest) != MoverKind::MemoryCell {
                return Err(Rbe::MoverisntMemory(*dest));
            }
            let dest_type = term_type(mover_defs, term);
            if dest_type != BOOL_TYPE_KEY {
                return Err(Rbe::TypeInequality(dest_type, BOOL_TYPE_KEY));
            }
            if filled.contains(*dest) {
                return Err(Rbe::Overwriting(*dest));
            }
            if let Some(mover_index) = in_term_out_set(&filled, term) {
                return Err(Rbe::ReadingUnfilled(mover_index));
            }
            filled.insert(*dest);
        }
        Instruction::CreateFromCall { dest, func, args } => {
            if mover_kind(mover_defs, *dest) != MoverKind::MemoryCell {
                return Err(Rbe::MoverisntMemory(*dest));
            }
            if filled.contains(*dest) {
                return Err(Rbe::Overwriting(*dest));
            }
            let dest_type = mover_type(mover_defs, *dest);
            if dest_type != func.ret_type {
                return Err(Rbe::TypeInequality(dest_type, func.ret_type));
            }
            if func.arg_types.len() != args.len() {
                return Err(Rbe::FuncHasWrongArgNumber {
                    other_has: args.len(),
                    func_has: func.arg_types.len(),
                });
            }
            for (&func_arg_type, arg_term) in func.arg_types.iter().zip(args.iter()) {
                let term_type = term_type(mover_defs, arg_term);
                if func_arg_type != term_type {
                    return Err(Rbe::TypeInequality(func_arg_type, term_type));
                }
            }
            if let Some(mover_index) = args.iter().find_map(|term| in_term_in_set(&filled, term)) {
                return Err(Rbe::ReadingUnfilled(mover_index));
            }
            filled.insert(*dest);
        }
        Instruction::Check(term) => {
            let term_type = term_type(mover_defs, term);
            if term_type != BOOL_TYPE_KEY {
                return Err(Rbe::TypeInequality(term_type, BOOL_TYPE_KEY));
            }
            if let Some(mover_index) = in_term_out_set(&filled, term) {
                return Err(Rbe::ReadingUnfilled(mover_index));
            }
        }
        Instruction::MemSwap(a, b) => {
            let [ta, tb] = [mover_type(mover_defs, *a), mover_type(mover_defs, *b)];
            if ta != tb {
                return Err(Rbe::TypeInequality(ta, tb));
            }
            for mover_index in [a, b] {
                if mover_kind(mover_defs, *mover_index) != MoverKind::MemoryCell {
                    return Err(Rbe::MoverisntMemory(*mover_index));
                }
                if !filled.contains(*mover_index) {
                    return Err(Rbe::ReadingUnfilled(*mover_index));
                }
            }
        }
    }
    Ok(())
}

fn rule_movements(
    mover_defs: &Vec<MoverDef>,
    filled: &mut IndexSet<2>,
    rule_def: &RuleDef,
) -> Result<(), RuleBuildError> {
    use RuleBuildError as Rbe;
    let mut busy_moving = IndexSet::<2>::default();
    for movement in rule_def.movements.iter() {
        // putter
        let putter_type_key = mover_type(mover_defs, movement.putter);
        if let MoverKind::GetterPort = mover_kind(mover_defs, movement.putter) {
            return Err(Rbe::MoverCannotPut(movement.putter));
        }
        if !busy_moving.insert(movement.putter) {
            return Err(Rbe::NotUniqueInMovements(movement.putter));
        }
        if !movement.putter_retains {
            if !filled.remove(movement.putter) {
                return Err(Rbe::ReadingUnfilled(movement.putter));
            }
        }
        // getters
        for getter in movement.getters.iter() {
            let getter_type_key = mover_type(mover_defs, getter);
            if putter_type_key != getter_type_key {
                return Err(Rbe::TypeInequality(putter_type_key, getter_type_key));
            }
            if let MoverKind::PutterPort = mover_kind(mover_defs, movement.putter) {
                return Err(Rbe::MoverCannotGet(getter));
            }
            if !busy_moving.insert(getter) {
                return Err(Rbe::NotUniqueInMovements(getter));
            }
            if !filled.insert(getter) {
                return Err(Rbe::Overwriting(getter));
            }
        }
        let clones = if movement.putter_retains { 1 } else { 0 } + movement.getters.len();
        if clones > 1 && putter_type_key.get_info().maybe_clone.is_none() {
            return Err(Rbe::MoverTypeMissingClone(movement.putter));
        }
    }
    if let Some(mover_index) =
        rule_def.ready.iter().filter(|mover_index| !busy_moving.contains(*mover_index)).next()
    {
        return Err(Rbe::ReadyButDoesntMove(mover_index));
    }
    Ok(())
}
