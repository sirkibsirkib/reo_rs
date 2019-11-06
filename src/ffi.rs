
use crate::building::{ProtoDef, MemInitial};
use crate::{ProtoHandle, Putter, Getter};
use libc::{c_void};
use std::ffi::CStr;
use std::os::raw::c_char;

// called from Reo-generated Rust code to create specialized constructors.
pub extern fn to_c_proto(proto: ProtoHandle) -> CProtoHandle {
	CProtoHandle { _p: proto }
}

////////////// PROTO //////////////

#[repr(C)]
pub struct CProtoHandle {
	_p: ProtoHandle
}

#[no_mangle]
pub extern fn reors_empty_proto_create() -> CProtoHandle {
	CProtoHandle {
		_p: ProtoDef {
			name_defs: Default::default(),
			rules: vec![],
		}.build(MemInitial::default()).unwrap()
	}
}

#[no_mangle]
pub unsafe extern fn reors_proto_handle_destroy(proto: &mut CProtoHandle) {
	std::ptr::drop_in_place(&mut (*proto)._p);
}

////////////// PORTS //////////////

#[repr(C)]
pub struct CPutter {
	_p: Putter<isize>
}

#[no_mangle]
pub unsafe extern fn reors_putter_claim(proto_handle: *mut CProtoHandle, name: *mut c_char) -> CPutter {
	println!("REORS TID {:?}", crate::TypeInfo::of::<isize>());
	let name = CStr::from_ptr(name).to_str().expect("BAD NAME STRING");
	let inner = Putter::<isize>::untyped_claim(&(*proto_handle)._p, name).expect("CLAIM WENT BAD");
	CPutter { _p: inner }
}

#[no_mangle]
pub unsafe extern fn reors_putter_put_raw(putter: *mut CPutter, datum: *mut *mut c_void) -> bool {
	(*putter)._p.put_raw(std::mem::transmute(datum))
}

#[no_mangle]
pub unsafe extern fn reors_putter_destroy(putter: *mut CPutter) {
	std::ptr::drop_in_place(&mut (*putter)._p);
}

///////

#[repr(C)]
pub struct CGetter {
	_p: Getter<isize>
}

#[no_mangle]
pub unsafe extern fn reors_getter_claim(proto_handle: *mut CProtoHandle, name: *mut c_char) -> CGetter {
	let name = CStr::from_ptr(name).to_str().expect("BAD NAME STRING");
	let inner = Getter::<isize>::untyped_claim(&(*proto_handle)._p, name).expect("CLAIM WENT BAD");
	CGetter { _p: inner }
}

#[no_mangle]
pub unsafe extern fn reors_getter_get_raw(getter: *mut CGetter, dest: *mut *mut c_void) {
	(*getter)._p.get_raw(std::mem::transmute(dest))
}

#[no_mangle]
pub unsafe extern fn reors_getter_destroy(getter: *mut CGetter) {
	std::ptr::drop_in_place(&mut (*getter)._p);
}