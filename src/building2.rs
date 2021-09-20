use crate::*;

pub struct ProtoDef {
    pub mover_def: HashMap<Name, MoverDef>,
    pub call_defs: HashMap<Name, CallHandle>,
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

pub struct MoverDef {
    pub type_key: TypeKey,
    pub mover_kind: MoverKind,
}

pub enum MoverKind {
    PutterPort,
    GetterPort,
    MemoryCell,
}

pub enum BuildError {}

impl ProtoDef {
    pub fn build(&self) -> Result<Proto, BuildError> {
        todo!()
    }
}
