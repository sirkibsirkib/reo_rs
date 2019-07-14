use super::*;
use std::collections::HashMap;

#[test]
pub fn type_info_eq() {
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u16>());
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u32>());
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u64>());
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u128>());
    assert!(TypeInfo::of::<u32>() != TypeInfo::of::<u64>());
    assert!(TypeInfo::of::<u32>() != TypeInfo::of::<u128>());
    assert!(TypeInfo::of::<u64>() != TypeInfo::of::<u128>());
}

#[test]
pub fn type_info_break() {
    let x: Box<dyn PortDatum> = Box::new(String::from("Oh hello, doggy."));
    let y: Box<dyn PortDatum> = Box::new(String::from("My, you're a tall one!"));
    let to_x: TraitObject = unsafe { transmute(x) };
    let to_y: TraitObject = unsafe { transmute(y) };
    assert_eq!(to_x.vtable, to_y.vtable);
    assert_eq!(to_x.vtable, TypeInfo::of::<Box<String>>().0);

    for data in [to_x.data, to_y.data].iter().copied() {
        let to = TraitObject {
            data,
            vtable: to_x.vtable,
        };
        let x: Box<dyn PortDatum> = unsafe { transmute(to) };
        drop(x);
    }
}

/// Note: not threadsafe at all! Need mutex for that
#[derive(Clone, PartialEq)]
struct Incrementor(*mut usize);
impl Drop for Incrementor {
    fn drop(&mut self) {
        unsafe { *self.0 += 1 }
    }
}

#[test]
pub fn drop_ok() {
    let mut drop_ctr: usize = 0;

    let x: Box<dyn PortDatum> = Box::new(Incrementor(&mut drop_ctr));
    let y: Box<dyn PortDatum> = Box::new(Incrementor(&mut drop_ctr));
    let to_x: TraitObject = unsafe { transmute(x) };
    let to_y: TraitObject = unsafe { transmute(y) };
    assert_eq!(to_x.vtable, to_y.vtable);
    assert_eq!(to_x.vtable, TypeInfo::of::<Box<Incrementor>>().0);

    // transmute does not invoke destructors
    assert_eq!(drop_ctr, 0);

    for (i, data) in [to_x.data, to_y.data].iter().copied().enumerate() {
        let vtable = to_y.vtable;
        let to = TraitObject { data, vtable };
        let x: Box<dyn PortDatum> = unsafe { transmute(to) };
        assert_eq!(drop_ctr, i);
        // destructors called as expected. memory has not been leaked
        drop(x);
        assert_eq!(drop_ctr, i + 1);
    }
}

#[test]
pub fn allocator_ok() {
    let mut drop_ctr: usize = 0;
    let mut alloc = Allocator::default();
    for _ in 0..5 {
        let x: Box<dyn PortDatum> = Box::new(Incrementor(&mut drop_ctr));
        alloc.store(x);
        let x: Box<dyn PortDatum> = Box::new(String::from("hi"));
        alloc.store(x);
    }
    assert_eq!(drop_ctr, 0);
    drop(alloc);
    assert_eq!(drop_ctr, 5);
}
