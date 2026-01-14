//! Byte-level database operations.
//!
//! This module provides functions for reading, writing, and patching bytes in the database.

use autocxx::prelude::*;

use crate::Address;
use crate::ffi::BADADDR;
use crate::ffi::bytes::*;

/// Read a single byte from the database.
pub fn get_byte(ea: Address) -> u8 {
    unsafe { idalib_get_byte(ea.into()) }
}

/// Read a 16-bit word from the database.
pub fn get_word(ea: Address) -> u16 {
    unsafe { idalib_get_word(ea.into()) }
}

/// Read a 32-bit dword from the database.
pub fn get_dword(ea: Address) -> u32 {
    unsafe { idalib_get_dword(ea.into()) }
}

/// Read a 64-bit qword from the database.
pub fn get_qword(ea: Address) -> u64 {
    unsafe { idalib_get_qword(ea.into()) }
}

/// Read multiple bytes from the database.
pub fn get_bytes(ea: Address, size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    let Ok(new_len) = (unsafe { idalib_get_bytes(ea.into(), &mut buf) }) else {
        return Vec::new();
    };
    unsafe {
        buf.set_len(new_len);
    }
    buf
}

/// Patch a single byte in the database.
///
/// Patching modifies the bytes but keeps track of the original values.
pub fn patch_byte(ea: Address, value: u8) -> bool {
    unsafe { idalib_patch_byte(ea.into(), value) }
}

/// Patch a 16-bit word in the database.
pub fn patch_word(ea: Address, value: u16) -> bool {
    unsafe { idalib_patch_word(ea.into(), value) }
}

/// Patch a 32-bit dword in the database.
pub fn patch_dword(ea: Address, value: u32) -> bool {
    unsafe { idalib_patch_dword(ea.into(), value) }
}

/// Patch a 64-bit qword in the database.
pub fn patch_qword(ea: Address, value: u64) -> bool {
    unsafe { idalib_patch_qword(ea.into(), value) }
}

/// Patch multiple bytes in the database.
pub fn patch_bytes(ea: Address, data: &[u8]) {
    unsafe { idalib_patch_bytes(ea.into(), data) }
}

/// Get the original byte value (before any patching).
pub fn get_original_byte(ea: Address) -> u8 {
    unsafe { idalib_get_original_byte(ea.into()) }
}

/// Get the original word value (before any patching).
pub fn get_original_word(ea: Address) -> u16 {
    unsafe { idalib_get_original_word(ea.into()) }
}

/// Get the original dword value (before any patching).
pub fn get_original_dword(ea: Address) -> u32 {
    unsafe { idalib_get_original_dword(ea.into()) }
}

/// Get the original qword value (before any patching).
pub fn get_original_qword(ea: Address) -> u64 {
    unsafe { idalib_get_original_qword(ea.into()) }
}

/// Revert a patched byte to its original value.
pub fn revert_byte(ea: Address) {
    unsafe { idalib_revert_byte(ea.into()) }
}

/// Put a byte directly in the database (not patching).
pub fn put_byte(ea: Address, value: u8) -> bool {
    unsafe { idalib_put_byte(ea.into(), value) }
}

/// Put a word directly in the database (not patching).
pub fn put_word(ea: Address, value: u16) {
    unsafe { idalib_put_word(ea.into(), value) }
}

/// Put a dword directly in the database (not patching).
pub fn put_dword(ea: Address, value: u32) {
    unsafe { idalib_put_dword(ea.into(), value) }
}

/// Put a qword directly in the database (not patching).
pub fn put_qword(ea: Address, value: u64) {
    unsafe { idalib_put_qword(ea.into(), value) }
}

/// Put multiple bytes directly in the database (not patching).
pub fn put_bytes(ea: Address, data: &[u8]) {
    unsafe { idalib_put_bytes(ea.into(), data) }
}

/// Delete items at the specified address range.
///
/// # Arguments
/// * `ea` - Starting address
/// * `flags` - Deletion flags (DELIT_* constants)
/// * `nbytes` - Number of bytes to delete
pub fn del_items(ea: Address, flags: i32, nbytes: u64) -> bool {
    unsafe { idalib_del_items(ea.into(), c_int(flags), nbytes) }
}

/// Create a byte data item at the specified address.
pub fn create_byte(ea: Address, length: u64) -> bool {
    unsafe { idalib_create_byte(ea.into(), length) }
}

/// Create a word data item at the specified address.
pub fn create_word(ea: Address, length: u64) -> bool {
    unsafe { idalib_create_word(ea.into(), length) }
}

/// Create a dword data item at the specified address.
pub fn create_dword(ea: Address, length: u64) -> bool {
    unsafe { idalib_create_dword(ea.into(), length) }
}

/// Create a qword data item at the specified address.
pub fn create_qword(ea: Address, length: u64) -> bool {
    unsafe { idalib_create_qword(ea.into(), length) }
}

/// Create a float data item at the specified address.
pub fn create_float(ea: Address, length: u64) -> bool {
    unsafe { idalib_create_float(ea.into(), length) }
}

/// Create a double data item at the specified address.
pub fn create_double(ea: Address, length: u64) -> bool {
    unsafe { idalib_create_double(ea.into(), length) }
}

/// Check if the address is mapped (has a segment).
pub fn is_mapped(ea: Address) -> bool {
    unsafe { idalib_is_mapped(ea.into()) }
}

/// Check if the address is loaded (has data/code).
pub fn is_loaded(ea: Address) -> bool {
    unsafe { idalib_is_loaded(ea.into()) }
}

/// Get the size of the item at the specified address.
pub fn get_item_size(ea: Address) -> u64 {
    unsafe { idalib_get_item_size(ea.into()) }
}

/// Get the end address of the item at the specified address.
pub fn get_item_end(ea: Address) -> Address {
    unsafe { idalib_get_item_end(ea.into()) }.into()
}

/// Get the head (start) of the item containing the specified address.
pub fn get_item_head(ea: Address) -> Address {
    unsafe { idalib_get_item_head(ea.into()) }.into()
}

/// Get the next address in the database.
pub fn next_addr(ea: Address) -> Option<Address> {
    let addr = unsafe { idalib_next_addr(ea.into()) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Get the previous address in the database.
pub fn prev_addr(ea: Address) -> Option<Address> {
    let addr = unsafe { idalib_prev_addr(ea.into()) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Get the next non-tail address.
pub fn next_not_tail(ea: Address) -> Option<Address> {
    let addr = unsafe { idalib_next_not_tail(ea.into()) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Get the previous non-tail address.
pub fn prev_not_tail(ea: Address) -> Option<Address> {
    let addr = unsafe { idalib_prev_not_tail(ea.into()) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Find the next unknown (unexplored) address.
pub fn next_unknown(ea: Address, maxea: Address) -> Option<Address> {
    let addr = unsafe { idalib_next_unknown(ea.into(), maxea.into()) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Find the previous unknown (unexplored) address.
pub fn prev_unknown(ea: Address, minea: Address) -> Option<Address> {
    let addr = unsafe { idalib_prev_unknown(ea.into(), minea.into()) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Find the next code address.
pub fn next_code(ea: Address, maxea: Address) -> Option<Address> {
    let addr = unsafe { idalib_next_that(ea.into(), maxea.into(), true) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Find the next data address.
pub fn next_data(ea: Address, maxea: Address) -> Option<Address> {
    let addr = unsafe { idalib_next_that(ea.into(), maxea.into(), false) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Find the previous code address.
pub fn prev_code(ea: Address, minea: Address) -> Option<Address> {
    let addr = unsafe { idalib_prev_that(ea.into(), minea.into(), true) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Find the previous data address.
pub fn prev_data(ea: Address, minea: Address) -> Option<Address> {
    let addr = unsafe { idalib_prev_that(ea.into(), minea.into(), false) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Address flags analysis helpers
pub mod flags {
    use super::*;

    /// Check if flags indicate a value is present.
    pub fn has_value(flags: u64) -> bool {
        unsafe { idalib_has_value(flags) }
    }

    /// Check if flags indicate a byte item.
    pub fn is_byte(flags: u64) -> bool {
        unsafe { idalib_is_byte(flags) }
    }

    /// Check if flags indicate a word item.
    pub fn is_word(flags: u64) -> bool {
        unsafe { idalib_is_word(flags) }
    }

    /// Check if flags indicate a dword item.
    pub fn is_dword(flags: u64) -> bool {
        unsafe { idalib_is_dword(flags) }
    }

    /// Check if flags indicate a qword item.
    pub fn is_qword(flags: u64) -> bool {
        unsafe { idalib_is_qword(flags) }
    }

    /// Check if flags indicate a float item.
    pub fn is_float(flags: u64) -> bool {
        unsafe { idalib_is_float(flags) }
    }

    /// Check if flags indicate a double item.
    pub fn is_double(flags: u64) -> bool {
        unsafe { idalib_is_double(flags) }
    }

    /// Check if flags indicate a head (start of item).
    pub fn is_head(flags: u64) -> bool {
        unsafe { idalib_is_head(flags) }
    }

    /// Check if flags indicate a tail (middle of item).
    pub fn is_tail(flags: u64) -> bool {
        unsafe { idalib_is_tail(flags) }
    }

    /// Check if flags indicate unknown/unexplored data.
    pub fn is_unknown(flags: u64) -> bool {
        unsafe { idalib_is_unknown(flags) }
    }

    /// Check if flags indicate a flow.
    pub fn is_flow(flags: u64) -> bool {
        unsafe { idalib_is_flow(flags) }
    }
}
