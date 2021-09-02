use super::*;

impl Allocator {
    pub fn new(type_map: Arc<TypeMap>) -> Self {
        Self {
            type_map,
            occupied: Default::default(),
            vacant: Default::default(),
        }
    }
    pub fn occupy_allocation(&mut self, type_key: TypeKey) -> DatumPtr {
        let Self { vacant, type_map, occupied } = self;
        let set = vacant.map.entry(type_key).or_insert_with(Default::default);
        let datum_ptr = set.iter().copied().next().unwrap_or_else(|| {
            let layout = type_map.get_type_info(&type_key).layout;
            let datum_ptr = DatumPtr::from_raw(unsafe { std::alloc::alloc(layout) });
            set.insert(datum_ptr);
            datum_ptr
        });
        occupied.insert(type_key, datum_ptr);
        datum_ptr
    }
    // pub fn get_a_vacant(&mut self, type_key: TypeKey) -> DatumPtr {
    //     let Self { vacant, type_map, .. } = self;
    //     let set = vacant.map.entry(type_key).or_insert_with(Default::default);
    //     set.iter().copied().next().unwrap_or_else(|| {
    //         let layout = type_map.get_type_info(&type_key).layout;
    //         let datum_ptr = DatumPtr::from_raw(unsafe { std::alloc::alloc(layout) });
    //         set.insert(datum_ptr);
    //         datum_ptr
    //     })
    // }
    pub fn swap_allocation_to(&mut self, type_key: TypeKey, datum_ptr: DatumPtr, to_occupied: bool) {
        // println!("to_occupied {} before: {:#?}", to_occupied, self);
        let [dest, src] = match to_occupied {
            true => [&mut self.occupied, &mut self.vacant],
            false => [&mut self.vacant, &mut self.occupied],
        };
        let removed = src.remove(type_key, datum_ptr);
        assert!(removed);
        dest.insert(type_key, datum_ptr);
    }
}
impl Drop for Allocator {
    fn drop(&mut self) {
        // drop all occupied contents
        for (type_key, datum_boxes) in self.occupied.map.iter() {
            let type_info  = self.type_map.get_type_info(type_key);
            if let Some(drop_func) = type_info.maybe_drop {
                for datum_box in datum_boxes.iter() {
                    unsafe { drop_func(datum_box.into_raw()) }
                }
            }
        }

        // drop all allocations
        for (type_key, datum_boxes) in self.occupied.map.iter().chain(self.vacant.map.iter()) {
            let type_info = self.type_map.get_type_info(type_key);
            for datum_box in datum_boxes.iter() {
                unsafe  { std::alloc::dealloc(datum_box.into_raw(), type_info.layout) }
            }
        }
        //DeBUGGY:println!("ALLOCATOR DROPPING DONE");
    }
}