use super::*;

impl TypeKey {
    pub fn get_info(self) -> &'static TypeInfo {
        self.0
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

impl std::hash::Hash for TypeKey {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        (self.0 as *const TypeInfo as usize).hash(h)
    }
}
impl PartialEq for TypeKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.0, other.0)
    }
}
impl Eq for TypeKey {}
impl TypeInfo {
    #[inline]
    fn new_raw_move_ptr<T>() -> unsafe fn(*mut u8, *const u8) {
        |dest, src| unsafe { (dest as *mut T).copy_from(src as *const T, 1) }
    }
    #[inline]
    fn new_clone_ptr<T: Clone>() -> unsafe fn(*mut u8, *const u8) {
        |dest, src| unsafe { (dest as *mut T).write((&*(src as *const T)).clone()) }
    }
    #[inline]
    fn new_eq_ptr<T: Eq>() -> unsafe fn(*const u8, *const u8) -> bool {
        |a, b| unsafe { (&*(a as *const T)).eq(&*(b as *const T)) }
    }
    #[inline]
    fn new_maybe_drop_ptr<T>() -> Option<unsafe fn(*mut u8)> {
        if std::mem::needs_drop::<T>() {
            Some(|ptr: *mut u8| unsafe { std::ptr::drop_in_place::<T>(ptr as *mut T) })
        } else {
            None
        }
    }
    pub fn new_clone_eq<T: Clone + Eq>() -> Self {
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
    pub fn new_no_clone_eq<T: Eq>() -> Self {
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
