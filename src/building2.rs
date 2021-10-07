use crate::*;

pub struct NameDefs {
    pub mover_defs: HashMap<Name, MoverDef>,
    pub call_defs: HashMap<Name, CallHandle>,
}

pub struct ProtoDef {
    pub name_defs: NameDefs,
    pub rules: Vec<RuleDef>,
}

pub struct RuleDef {
    pub instructions: Vec<Instruction<Name, Name>>,
    pub movements: Vec<MovementDef>,
}

pub struct MovementDef {
    pub putter: Name,
    pub putter_retains: bool,
    pub getters: Vec<Name>,
}

#[derive(Debug, Copy, Clone)]
pub struct MoverDef {
    pub type_key: TypeKey,
    pub mover_kind: MoverKind,
}

#[derive(Debug, Copy, Clone)]
pub enum MoverKind {
    PutterPort,
    GetterPort,
    MemoryCell,
}

pub enum BuildError {}

impl MoverDef {
    fn to_space(self) -> Space {
        let Self { type_key, mover_kind } = self;

        match self.mover_kind {
            MoverKind::PutterPort => {
                Space::PoPu { mb: Default::default(), ps: PutterSpace::new(type_key) }
            }
            MoverKind::GetterPort => Space::PoGe { mb: Default::default(), type_key },
            MoverKind::MemoryCell => Space::Memo { ps: PutterSpace::new(type_key) },
        }
    }
}

impl ProtoDef {
    fn build_rules(&self, rules: &[RuleDef]) -> Result<Vec<Rule>, BuildError> {
        rules.iter().map(|rule| self.name_defs.build_rule(rule)).collect()
    }
    pub fn build(&self) -> Result<Proto, BuildError> {
        // build spaces from namedefs
        let mut spaces = vec![];
        let mut name_mapping = HashMap::<Name, SpaceIndex>::default();
        for (&name, mover_def) in self.name_defs.mover_defs.iter() {
            let space_index = SpaceIndex(spaces.len());
            spaces.push(mover_def.to_space());
            name_mapping.insert(name, space_index);
        }
        todo!()
    }
}
impl NameDefs {
    fn build_rule(&self, rules: &RuleDef) -> Result<Rule, BuildError> {
        todo!()
    }
}
