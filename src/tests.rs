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

#[test]
pub fn trait_obj_changing() {
    // task: invoke this dynamically-dispatched function using different forms
    // note: all the chosen forms have the same IN-MEMORY representation, just
    //   different ownership semantics. Arc<...> is different in some ways to Box<...>.
    // use `val` to see if it worked.

    let mut val: usize = 0;
    let mut x: Box<dyn FnMut()> = Box::new(|| val += 1);
    x(); // as owned heap allocation

    let x: &mut dyn FnMut() = unsafe { transmute(x) };
    x(); // as borrowed heap allocation

    let x: *mut dyn FnMut() = unsafe { transmute(x) };
    unsafe { (*x)() }; // as raw heap pointer

    assert_eq!(val, 3);

    // drop x again
    let x: Box<dyn FnMut()> = unsafe { transmute(x) };
    drop(x);
}

/// Note: not threadsafe at all! Need mutex for that
impl PartialEq for Incrementor {
    fn eq(&self, other: &Self) -> bool {
        true
    }
}
#[derive(Clone)]
struct Incrementor(Arc<Mutex<usize>>);
impl Drop for Incrementor {
    fn drop(&mut self) {
        *self.0.lock() += 1
    }
}

#[test]
pub fn drop_ok() {
    let m = Arc::new(Mutex::new(0));

    let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
    let y: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
    let to_x: TraitObject = unsafe { transmute(x) };
    let to_y: TraitObject = unsafe { transmute(y) };
    assert_eq!(to_x.vtable, to_y.vtable);

    // transmute does not invoke destructors
    assert_eq!(*m.lock(), 0);

    for (i, data) in [to_x.data, to_y.data].iter().copied().enumerate() {
        let vtable = to_y.vtable;
        let to = TraitObject { data, vtable };
        let x: Box<dyn PortDatum> = unsafe { transmute(to) };
        assert_eq!(*m.lock(), i);
        // destructors called as expected. memory has not been leaked
        drop(x);
        assert_eq!(*m.lock(), i + 1);
    }
}

#[test]
pub fn allocator_ok() {
    let m = Arc::new(Mutex::new(0));
    let mut alloc = Allocator::default();
    for _ in 0..5 {
        let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
        alloc.store(x);
        let x: Box<dyn PortDatum> = Box::new(String::from("hi"));
        alloc.store(x);
    }
    assert_eq!(*m.lock(), 0);
    drop(alloc);
    assert_eq!(*m.lock(), 5);
}

#[test]
pub fn allocator_drop_inside() {
    let m = Arc::new(Mutex::new(0));

    let mut alloc = Allocator::default();
    let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
    let (data, info) = unsafe { trait_obj_read(&x) };
    alloc.store(x);

    assert_eq!(*m.lock(), 0);
    // contents of x are dropped
    assert!(alloc.drop_inside(data, info));

    assert_eq!(*m.lock(), 1);

    // dropping it repeatedly fails
    assert!(!alloc.drop_inside(data, info));
    assert_eq!(*m.lock(), 1);

    drop(alloc); // box for x itself is dropped
}

#[test]
pub fn allocator_reuse() {
    let m = Arc::new(Mutex::new(0));

    let mut alloc = Allocator::default();
    let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
    let (data, info) = unsafe { trait_obj_read(&x) };
    alloc.store(x);

    assert_eq!(*m.lock(), 0);
    assert!(alloc.drop_inside(data, info));
    assert_eq!(*m.lock(), 1);

    for i in 0..5 {
        let new_data = unsafe {
            let new_data = alloc.alloc_uninit(info);
            assert_eq!(new_data, data);
            let data: *mut Incrementor = transmute(new_data);
            data.write(Incrementor(m.clone()));
            new_data
        };
        assert_eq!(*m.lock(), i + 1);
        assert!(alloc.drop_inside(new_data, info));
        assert_eq!(*m.lock(), i + 2);
    }

    drop(alloc);
    assert_eq!(*m.lock(), 6);
}

#[test]
pub fn get_layout_from_trait() {
    let m = Arc::new(Mutex::new(0));

    let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
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
    let m = Arc::new(Mutex::new(0));

    let x: Box<dyn PortDatum> = Box::new(Incrementor(m.clone()));
    let (_, i) = unsafe { trait_obj_read(&x) };
    assert_eq!(x.my_layout(), i.get_layout());

    let x: Box<dyn PortDatum> = Box::new(true);
    let (_, i) = unsafe { trait_obj_read(&x) };
    assert_eq!(x.my_layout(), i.get_layout());
}

#[test]
pub fn allocator_fresh_alloc() {
    let m = Arc::new(Mutex::new(0));

    let mut alloc = Allocator::default();
    let type_info = TypeInfo::of::<Incrementor>();

    let new_data = unsafe {
        let new_data = alloc.alloc_uninit(type_info);
        let data: *mut Incrementor = transmute(new_data);
        data.write(Incrementor(m.clone()));
        new_data
    };

    let new_data2 = unsafe {
        let new_data2 = alloc.alloc_uninit(type_info);
        let data2: *mut Incrementor = transmute(new_data2);
        data2.write(Incrementor(m.clone()));
        new_data2
    };

    alloc.drop_inside(new_data, type_info);
    assert_eq!(*m.lock(), 1);

    drop(alloc);
    assert_eq!(*m.lock(), 2);
}

#[test]
fn call_handle() {
    let mut x = 5;

    let b: Arc<dyn Fn(*mut u32)> = Arc::new(|dest| unsafe { dest.write(3) });
    let ch = CallHandle {
        func: unsafe { transmute(b) },
        ret: TypeInfo::of::<u32>(),
        args: vec![],
    };

    let dest: *mut u32 = &mut x;
    let funcy: Arc<dyn Fn(*mut u32)> = unsafe { transmute(ch.func) };
    funcy(dest);

    std::mem::forget(funcy);
    println!("x={:?}", x);
}

#[test]
fn call_handle_2() {
    unsafe {
        let mut x = 5;

        let b: Arc<dyn Fn(*mut u32)> = Arc::new(|dest| dest.write(3));
        let ch = CallHandle {
            func: transmute(b),
            ret: TypeInfo::of::<u32>(),
            args: vec![],
        };

        let dest: *mut u32 = &mut x;
        let dest: TraitData = transmute(dest);
        let funcy: &Arc<dyn Fn(TraitData)> = transmute(&ch.func);
        funcy(dest);

        std::mem::forget(funcy);
        println!("x={:?}", x);
    }
}

lazy_static::lazy_static! {
    static ref SYNC_U32: ProtoDef = ProtoDef {
        name_defs: hashmap! {
            "A" => NameDef::Port { is_putter:true, type_info: TypeInfo::of::<u32>() },
            "B" => NameDef::Port { is_putter:false, type_info: TypeInfo::of::<u32>() },
        },
        rules: vec![RuleDef {
            state_guard: StatePredicate {
                ready_ports: hashset! {"A", "B"},
                full_mem: hashset! {},
                empty_mem: hashset! {},
            },
            ins: vec![],
            output: hashmap! {
                "A" => (false, hashset!{"B"})
            },
        }],
    };
}

#[test]
fn sync_create() {
    build_proto(&SYNC_U32, MemInitial::default()).unwrap();
}

#[test]
pub fn send_sync_proto() {
    let x: MaybeUninit<ProtoCr> = MaybeUninit::uninit();
    let b = std::thread::spawn(move || {
        let y = x;
        std::mem::forget(y);
    });
    b.join().unwrap();
}

#[test]
fn sync_claim() {
    let p = build_proto(&SYNC_U32, MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<u32>, Getter<u32>) = (
        Putter::claim(&p, "A").unwrap(),
        Getter::claim(&p, "B").unwrap(),
    );

    let a = std::thread::spawn(move || {
        p.put(32);
    });
    let b = std::thread::spawn(move || {
        let x = g.get();
    });
    a.join().unwrap();
    b.join().unwrap();
}

#[test]
fn sync_put_get() {
    let p = build_proto(&SYNC_U32, MemInitial::default()).unwrap();
    let (mut p, mut g): (Putter<u32>, Getter<u32>) = (
        Putter::claim(&p, "A").unwrap(),
        Getter::claim(&p, "B").unwrap(),
    );

    let a = std::thread::spawn(move || {
        p.put(32);
    });
    let b = std::thread::spawn(move || {
        let x = g.get();
    });
    a.join().unwrap();
    b.join().unwrap();
}
