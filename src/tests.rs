use super::*;
use std::collections::HashMap;

#[test]
pub fn type_info_neq() {
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u16>());
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u32>());
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u64>());
    assert!(TypeInfo::of::<u8>() != TypeInfo::of::<u128>());
    assert!(TypeInfo::of::<u32>() != TypeInfo::of::<u64>());
    assert!(TypeInfo::of::<u32>() != TypeInfo::of::<u128>());
    assert!(TypeInfo::of::<u64>() != TypeInfo::of::<u128>());
}

#[test]
pub fn type_info_eq() {
    let x: Box<dyn PortDatum> = Box::new(5u8);
    let y: Box<dyn PortDatum> = Box::new(String::from("Hello"));
    let z: Box<dyn PortDatum> = Box::new(String::from("Howdy"));
    unsafe {
        let (data_x, info_x) = trait_obj_read(&x);
        let (data_y, info_y) = trait_obj_read(&y);
        let (data_z, info_z) = trait_obj_read(&z);

        // string and u8 have different vtables
        assert!(info_x.0 != info_y.0);
        // y and z both use the same String vtable
        assert_eq!(info_y.0, info_z.0);
    }
    // x,y,z dropped
}

#[test]
pub fn type_info_break() {
    let x: Box<dyn PortDatum> = Box::new(String::from("Oh hello, doggy."));
    let y: Box<dyn PortDatum> = Box::new(String::from("My, you're a tall one!"));
    let to_x: TraitObject = unsafe { transmute(x) };
    let to_y: TraitObject = unsafe { transmute(y) };
    assert_eq!(to_x.vtable, to_y.vtable);
    // assert_eq!(to_x.vtable, TypeInfo::of::<Box<dyn String>>().0);

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

#[test]
pub fn allocator_drop_inside() {
    let mut drop_ctr: usize = 0;

    let mut alloc = Allocator::default();
    let x: Box<dyn PortDatum> = Box::new(Incrementor(&mut drop_ctr));
    let (data, info) = unsafe { trait_obj_read(&x) };
    alloc.store(x);

    assert_eq!(drop_ctr, 0);
    // contents of x are dropped
    assert!(alloc.drop_inside(data, info));

    assert_eq!(drop_ctr, 1);

    // dropping it repeatedly fails
    assert!(!alloc.drop_inside(data, info));
    assert_eq!(drop_ctr, 1);

    drop(alloc); // box for x itself is dropped
}

#[test]
pub fn allocator_reuse() {
    let mut drop_ctr: usize = 0;

    let mut alloc = Allocator::default();
    let x: Box<dyn PortDatum> = Box::new(Incrementor(&mut drop_ctr));
    let (data, info) = unsafe { trait_obj_read(&x) };
    alloc.store(x);

    assert_eq!(drop_ctr, 0);
    assert!(alloc.drop_inside(data, info));
    assert_eq!(drop_ctr, 1);

    for i in 0..5 {
        let new_data = alloc.alloc_uninit(info);
        assert_eq!(new_data, data);
        let data: &mut Incrementor = unsafe { transmute(new_data) };
        data.0 = &mut drop_ctr; // now it's initialized

        assert_eq!(drop_ctr, i + 1);
        assert!(alloc.drop_inside(new_data, info));
        assert_eq!(drop_ctr, i + 2);
    }

    drop(alloc);
    assert_eq!(drop_ctr, 6);
}

#[test]
pub fn get_layout_from_trait() {
    let mut x: usize = 0;

    let x: Box<dyn PortDatum> = Box::new(Incrementor(&mut x));
    let layout = x.my_layout();
    assert_eq!(layout.size(), 8);
    assert_eq!(layout.align(), 8);

    let x: Box<dyn PortDatum> = Box::new(true);
    let layout = x.my_layout();
    assert_eq!(layout.size(), 1);
    assert_eq!(layout.align(), 1);
}

#[test]
pub fn get_layout_raw_eq() {
    let mut x: usize = 0;

    let x: Box<dyn PortDatum> = Box::new(Incrementor(&mut x));
    let (_, i) = unsafe { trait_obj_read(&x) };
    assert_eq!(x.my_layout(), i.get_layout());

    let x: Box<dyn PortDatum> = Box::new(true);
    let (_, i) = unsafe { trait_obj_read(&x) };
    assert_eq!(x.my_layout(), i.get_layout());
}

#[test]
pub fn allocator_fresh_alloc() {
    let mut drop_ctr: usize = 0;

    let mut alloc = Allocator::default();
    let type_info = TypeInfo::of::<Incrementor>();

    let new_data = alloc.alloc_uninit(type_info);
    let data: &mut Incrementor = unsafe { transmute(new_data) };
    data.0 = &mut drop_ctr; // now it's initialized

    let new_data2 = alloc.alloc_uninit(type_info);
    let data2: &mut Incrementor = unsafe { transmute(new_data2) };
    data2.0 = &mut drop_ctr; // now it's initialized

    alloc.drop_inside(new_data, type_info);
    assert_eq!(drop_ctr, 1);

    drop(alloc);
    assert_eq!(drop_ctr, 2);
}


#[test]
fn call_handle() {
    let mut x = 5;

    let b: Box<dyn Fn(*mut u32)> = Box::new(|dest| unsafe { dest.write(3) });
    let ch = CallHandle {
        func: unsafe { transmute(b) },
        ret: TypeInfo::of::<u32>(),
        args: vec![],
    };

    let dest: *mut u32 = &mut x;
    let funcy: Box<dyn Fn(*mut u32)> = unsafe { transmute(ch.func) };
    funcy(dest);

    std::mem::forget(funcy);
    println!("x={:?}", x);
}


#[test]
fn call_handle_2() {
    unsafe {
        let mut x = 5;

        let b: Box<dyn Fn(*mut u32)> = Box::new(|dest| dest.write(3));
        let ch = CallHandle {
            func: transmute(b),
            ret: TypeInfo::of::<u32>(),
            args: vec![],
        };

        let dest: *mut u32 = &mut x;
        let dest: TraitData = transmute(dest);
        let funcy: &Box<dyn Fn(TraitData)> = transmute(&ch.func);
        funcy(dest);

        std::mem::forget(funcy);
        println!("x={:?}", x);
    }
}