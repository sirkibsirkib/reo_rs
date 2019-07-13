
    // SENSITIVE STRUCTURE
    // struct MemDef {
    // 	init: ManuallyDrop<Option<Box<u8>>>,
    // 	type_id: TypeId,
    // 	drop_fn: unsafe fn(*mut Box<u8>),
    // }
    // impl MemDef {
    // 	pub fn new_with_tid(type_id: TypeId) -> Self {
    // 		Self {
    // 			init: ManuallyDrop::new(None),
    // 			type_id,
    // 			drop_fn: std::intrinsics::drop_in_place::<Box<u8>>,
    // 		}
    // 	}
    // 	pub fn new<T: 'static>(init: Option<Box<T>>) -> Self {
    // 		let init = unsafe {std::mem::transmute(init)};
    // 		let drop_fn: unsafe fn(*mut Box<T>) = std::intrinsics::drop_in_place::<Box<T>>;
    // 		let drop_fn = unsafe {std::mem::transmute(drop_fn)};
    // 		Self {
    // 			type_id: TypeId::of::<T>(),
    // 			init,
    // 			drop_fn,
    // 		}
    // 	}
    // }
    // impl Drop for MemDef {
    // 	fn drop(&mut self) {
    // 		if let Some(b) = self.init {
    // 			unsafe { 
    // 				self.drop_fn()
    // 			}
    // 		}
    // 	}
    // }