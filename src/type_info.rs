use super::*;

impl TypeMap {
    pub fn get_type_info(&self, type_key: &TypeKey) -> &TypeInfo {
        self.type_infos.get(&type_key).expect("unknown key!")
    }
}
impl TypedAllocations {
    pub fn insert(&mut self, type_key: TypeKey, datum_ptr: DatumPtr) -> bool {
        self.map.entry(type_key).or_insert_with(Default::default).insert(datum_ptr)
    }
    pub fn remove(&mut self, type_key: TypeKey, datum_ptr: DatumPtr) -> bool {
        self.map.get_mut(&type_key).map(|set| set.remove(&datum_ptr)).unwrap_or(false)
    }
}
impl TypeInfo {
    #[inline]
    pub fn new_raw_move_ptr<T>() -> unsafe fn( *mut u8, *const u8) {
        |dest, src| unsafe { (dest as *mut T).write((src as *const T).read()) }
    }
    #[inline]
    pub fn new_clone_ptr<T: Clone>() -> unsafe fn(*mut u8, *const u8) {
        |dest, src| unsafe {*(dest as *mut T) = (&*(src as *const T)).clone() }
    }
    #[inline]
    pub fn new_eq_ptr<T: Eq>() -> unsafe fn(*const u8, *const u8) -> bool {
        |a, b| unsafe { (&*(a as *const T)).eq(&*(b as *const T)) }
    }
    #[inline]
    pub fn new_maybe_drop_ptr<T>() -> Option<unsafe fn(*mut u8)> {
        if std::mem::needs_drop::<T>() {
            Some( |ptr| unsafe { drop((ptr as *const T).read()) })
        } else {
            None
        }
    }
    pub fn new_clone_eq<T: Clone + Eq>() -> Self  {
        Self {
            layout: Layout::new::<T>(),
            raw_move: Self::new_raw_move_ptr::<T>(),
            maybe_clone: Some(Self::new_clone_ptr::<T>()),
            maybe_eq: Some(Self::new_eq_ptr::<T>()),
            maybe_drop: Self::new_maybe_drop_ptr::<T>(),
        }
    }
    pub fn new_clone_no_eq<T: Clone>() -> Self {
        Self {
            layout: Layout::new::<T>(),
            raw_move: Self::new_raw_move_ptr::<T>(),
            maybe_clone: Some(Self::new_clone_ptr::<T>()),
            maybe_eq: None,
            maybe_drop: Self::new_maybe_drop_ptr::<T>(),
        }
    }
    pub fn new_no_clone_eq<T: Eq>() -> Self  {
        Self {
            layout: Layout::new::<T>(),
            raw_move: Self::new_raw_move_ptr::<T>(),
            maybe_clone: None,
            maybe_eq: Some(Self::new_eq_ptr::<T>()),
            maybe_drop: Self::new_maybe_drop_ptr::<T>(),
        }
    }
    pub fn new_no_clone_no_eq<T>() -> Self {
        Self {
            layout: Layout::new::<T>(),
            raw_move: Self::new_raw_move_ptr::<T>(),
            maybe_clone: None,
            maybe_eq: None,
            maybe_drop: Self::new_maybe_drop_ptr::<T>(),
        }
    }
}
impl TypeInfo {
    pub fn is_copy(&self) -> bool {
        self.maybe_drop.is_none()
    }
    pub(crate) unsafe fn try_drop_data(&self, data: DatumPtr) {
        if let Some(drop_func) = self.maybe_drop {
            drop_func(data.into_raw())
        }
    }
}