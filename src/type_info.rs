use super::*;

impl TypeProtected<ProtoHandle> {
    pub fn get_inner(&self) -> &ProtoHandle {
        &self.0
    }
}

impl Default for TypeProtected<TypeMap> {
    fn default() -> Self {
        let bool_type_key = TypeKey::from_type_id::<bool>();
        Self(TypeMap {
            bool_type_key,
            type_infos: hashmap! {
                bool_type_key => TypeInfo::new_clone_eq::<bool>(),
            },
        })
    }
}
impl TypeProtected<TypeMap> {
    pub fn add_no_clone_no_eq<T: 'static>(&mut self) -> TypeKey {
        let type_key = TypeKey::from_type_id::<T>();
        self.0.type_infos.entry(type_key).or_insert_with(TypeInfo::new_no_clone_no_eq::<T>);
        type_key
    }
    pub fn add_no_clone_eq<T: 'static + Eq>(&mut self) -> TypeKey {
        let type_key = TypeKey::from_type_id::<T>();
        self.0.type_infos.entry(type_key).or_insert_with(TypeInfo::new_no_clone_eq::<T>);
        type_key
    }
    pub fn add_clone_no_eq<T: 'static + Clone>(&mut self) -> TypeKey {
        let type_key = TypeKey::from_type_id::<T>();
        self.0.type_infos.entry(type_key).or_insert_with(TypeInfo::new_clone_no_eq::<T>);
        type_key
    }
    pub fn add_clone_eq<T: 'static + Eq + Clone>(&mut self) -> TypeKey {
        let type_key = TypeKey::from_type_id::<T>();
        self.0.type_infos.entry(type_key).or_insert_with(TypeInfo::new_clone_eq::<T>);
        type_key
    }
}
impl TypeKey {
    pub fn from_type_id<T: 'static>() -> Self {
        unsafe { std::mem::transmute(std::any::TypeId::of::<T>()) }
    }
}
impl TypeMap {
    pub fn add(&mut self, type_key: TypeKey, type_info: TypeInfo) {
        self.type_infos.entry(type_key).or_insert(type_info);
    }
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
    pub fn new_raw_move_ptr<T>() -> unsafe fn(*mut u8, *const u8) {
        |dest, src| unsafe { (dest as *mut T).copy_from(src as *const T, 1) }
    }
    #[inline]
    pub fn new_clone_ptr<T: Clone>() -> unsafe fn(*mut u8, *const u8) {
        |dest, src| unsafe { (dest as *mut T).write((&*(src as *const T)).clone()) }
    }
    #[inline]
    pub fn new_eq_ptr<T: Eq>() -> unsafe fn(*const u8, *const u8) -> bool {
        |a, b| unsafe { (&*(a as *const T)).eq(&*(b as *const T)) }
    }
    #[inline]
    pub fn new_maybe_drop_ptr<T>() -> Option<unsafe fn(*mut u8)> {
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
