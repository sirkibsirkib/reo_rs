
use crate::{ProtoHandle, Putter, Getter};
use libc::{c_void, intptr_t};
use std::ffi::CStr;
use std::os::raw::c_char;

// called from Reo-generated Rust code to create specialized constructors.
pub fn to_c_proto(proto: ProtoHandle) -> CProtoHandle {
	CProtoHandle(proto)
}

////////////// PROTO //////////////

#[repr(C)]
pub struct CProtoHandle(ProtoHandle);

#[no_mangle]
pub unsafe fn c_proto_handle_destroy(proto: *mut CProtoHandle) {
	std::ptr::drop_in_place(&mut (*proto).0);
}

////////////// PORTS //////////////

#[repr(C)]
pub struct CPutter(Putter<intptr_t>);

#[no_mangle]
pub unsafe fn c_putter_claim(proto_handle: *mut CProtoHandle, name: *mut c_char) -> CPutter {
	let name = CStr::from_ptr(name).to_str().expect("BAD NAME STRING");
	let inner = Putter::<intptr_t>::claim(&(*proto_handle).0, name).expect("CLAIM WENT BAD");
	CPutter(inner)
}

#[no_mangle]
pub unsafe fn c_putter_put_raw(putter: *mut CPutter, datum: *mut *mut c_void) -> bool {
	(*putter).0.put_raw(std::mem::transmute(datum))
}

#[no_mangle]
pub unsafe fn c_putter_destroy(putter: *mut CPutter) {
	std::ptr::drop_in_place(&mut (*putter).0);
}

///////

#[repr(C)]
pub struct CGetter(Getter<intptr_t>);

#[no_mangle]
pub unsafe fn c_getter_claim(proto_handle: *mut CProtoHandle, name: *mut c_char) -> CGetter {
	let name = CStr::from_ptr(name).to_str().expect("BAD NAME STRING");
	let inner = Getter::<intptr_t>::claim(&(*proto_handle).0, name).expect("CLAIM WENT BAD");
	CGetter(inner)
}

#[no_mangle]
pub unsafe fn c_getter_get_raw(getter: *mut CGetter, dest: *mut *mut c_void) {
	(*getter).0.get_raw(std::mem::transmute(dest))
}

#[no_mangle]
pub unsafe fn c_getter_destroy(getter: *mut CGetter) {
	std::ptr::drop_in_place(&mut (*getter).0);
}