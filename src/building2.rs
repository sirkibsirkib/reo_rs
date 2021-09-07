use crate::building::{NameDef, ProtoDef};
use crate::*;

pub enum BuildErr {}

trait VecIdxPush<T> {
    fn push_to_index(&mut self, t: T) -> usize;
}

impl VecIdxPush<Space> for Vec<Space> {
    fn push_to_index(&mut self, space: Space) -> usize {
        self.push(space);
        self.len() - 1
    }
}

impl ProtoDef {
    fn perm_spaces(&self) -> (Vec<Space>, HashMap<Name, SpaceIndex>) {
        let mut spaces = Vec::<Space>::default();
        let mut name_mapping = HashMap::<Name, SpaceIndex>::default();
        for (name, name_def) in self.name_defs.iter() {
            let space = match name_def {
                NameDef::Mem { type_key } => Space::Memo { ps: PutterSpace::new(*type_key) },
                NameDef::Port { type_key, is_putter: false } => {
                    Space::PoGe { mb: Default::default(), type_key: *type_key }
                }
                NameDef::Port { type_key, is_putter: true } => {
                    Space::PoPu { mb: Default::default(), ps: PutterSpace::new(*type_key) }
                }
                NameDef::Func(_call_handle) => continue,
            };
            name_mapping.insert(*name, SpaceIndex(spaces.push_to_index(space)));
        }
        (spaces, name_mapping)
    }

    pub fn build2(&self) -> Result<Proto, BuildErr> {
        let (mut spaces, name_mapping) = self.perm_spaces();
        // permanent spaces and name_mapping
        // for space

        todo!()
    }
}
