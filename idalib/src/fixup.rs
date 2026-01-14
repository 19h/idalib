//! Fixup (relocation) information.
//!
//! This module provides functions to work with fixup information in the database.

use bitflags::bitflags;

use autocxx::prelude::*;

use crate::Address;
use crate::ffi::BADADDR;
use crate::ffi::fixup as ffi_fixup;
use crate::ffi::fixup::*;

/// Fixup types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FixupType {
    Off8 = ffi_fixup::types::FIXUP_OFF8,
    Off16 = ffi_fixup::types::FIXUP_OFF16,
    Seg16 = ffi_fixup::types::FIXUP_SEG16,
    Ptr16 = ffi_fixup::types::FIXUP_PTR16,
    Off32 = ffi_fixup::types::FIXUP_OFF32,
    Ptr32 = ffi_fixup::types::FIXUP_PTR32,
    Hi8 = ffi_fixup::types::FIXUP_HI8,
    Hi16 = ffi_fixup::types::FIXUP_HI16,
    Low8 = ffi_fixup::types::FIXUP_LOW8,
    Low16 = ffi_fixup::types::FIXUP_LOW16,
    Off64 = ffi_fixup::types::FIXUP_OFF64,
    Off8S = ffi_fixup::types::FIXUP_OFF8S,
    Off16S = ffi_fixup::types::FIXUP_OFF16S,
    Off32S = ffi_fixup::types::FIXUP_OFF32S,
    Custom(u16),
}

impl From<u16> for FixupType {
    fn from(value: u16) -> Self {
        match value {
            13 => FixupType::Off8,
            1 => FixupType::Off16,
            2 => FixupType::Seg16,
            3 => FixupType::Ptr16,
            4 => FixupType::Off32,
            5 => FixupType::Ptr32,
            6 => FixupType::Hi8,
            7 => FixupType::Hi16,
            8 => FixupType::Low8,
            9 => FixupType::Low16,
            12 => FixupType::Off64,
            14 => FixupType::Off8S,
            15 => FixupType::Off16S,
            16 => FixupType::Off32S,
            v if v >= 0x8000 => FixupType::Custom(v),
            _ => FixupType::Custom(value),
        }
    }
}

impl From<FixupType> for u16 {
    fn from(value: FixupType) -> Self {
        match value {
            FixupType::Off8 => 13,
            FixupType::Off16 => 1,
            FixupType::Seg16 => 2,
            FixupType::Ptr16 => 3,
            FixupType::Off32 => 4,
            FixupType::Ptr32 => 5,
            FixupType::Hi8 => 6,
            FixupType::Hi16 => 7,
            FixupType::Low8 => 8,
            FixupType::Low16 => 9,
            FixupType::Off64 => 12,
            FixupType::Off8S => 14,
            FixupType::Off16S => 15,
            FixupType::Off32S => 16,
            FixupType::Custom(v) => v,
        }
    }
}

bitflags! {
    /// Fixup flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FixupFlags: u32 {
        /// Fixup is relative to the linear address base
        const REL = ffi_fixup::flags::FIXUPF_REL;
        /// Target is a location (otherwise - segment)
        const EXTDEF = ffi_fixup::flags::FIXUPF_EXTDEF;
        /// Fixup is ignored by IDA
        const UNUSED = ffi_fixup::flags::FIXUPF_UNUSED;
        /// Fixup was not present in the input file
        const CREATED = ffi_fixup::flags::FIXUPF_CREATED;
    }
}

/// Fixup information
#[derive(Debug, Clone)]
pub struct Fixup {
    pub source: Address,
    pub fixup_type: FixupType,
    pub flags: FixupFlags,
    pub sel: Address,
    pub off: Address,
    pub displacement: i64,
}

/// Check if a fixup exists at the given address.
pub fn exists_fixup(source: Address) -> bool {
    unsafe { idalib_exists_fixup(source.into()) }
}

/// Get fixup information at the given address.
pub fn get_fixup(source: Address) -> Option<Fixup> {
    let mut fixup_type: u16 = 0;
    let mut flags: u32 = 0;
    let mut sel = 0u64.into();
    let mut off = 0u64.into();
    let mut displacement: i64 = 0;

    let found = unsafe {
        idalib_get_fixup(
            source.into(),
            &mut fixup_type,
            &mut flags,
            &mut sel,
            &mut off,
            &mut displacement,
        )
    };

    if found {
        Some(Fixup {
            source,
            fixup_type: FixupType::from(fixup_type),
            flags: FixupFlags::from_bits_truncate(flags),
            sel: sel.into(),
            off: off.into(),
            displacement,
        })
    } else {
        None
    }
}

/// Set fixup information at the given address.
pub fn set_fixup(fixup: &Fixup) {
    unsafe {
        idalib_set_fixup(
            fixup.source.into(),
            u16::from(fixup.fixup_type),
            fixup.flags.bits(),
            fixup.sel.into(),
            fixup.off.into(),
            fixup.displacement,
        )
    }
}

/// Delete fixup information at the given address.
pub fn del_fixup(source: Address) {
    unsafe { idalib_del_fixup(source.into()) }
}

/// Get the first address with fixup information.
pub fn get_first_fixup_ea() -> Option<Address> {
    let addr = unsafe { idalib_get_first_fixup_ea() };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Get the next address with fixup information.
pub fn get_next_fixup_ea(ea: Address) -> Option<Address> {
    let addr = unsafe { idalib_get_next_fixup_ea(ea.into()) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Get the previous address with fixup information.
pub fn get_prev_fixup_ea(ea: Address) -> Option<Address> {
    let addr = unsafe { idalib_get_prev_fixup_ea(ea.into()) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Check if the specified range contains any fixups.
pub fn contains_fixups(ea: Address, size: u64) -> bool {
    unsafe { idalib_contains_fixups(ea.into(), size) }
}

/// Apply fixup information for an address.
pub fn apply_fixup(item_ea: Address, fixup_ea: Address, n: i32, is_macro: bool) -> bool {
    unsafe { idalib_apply_fixup(item_ea.into(), fixup_ea.into(), c_int(n), is_macro) }
}

/// Get the operand value from fixup bytes.
pub fn get_fixup_value(ea: Address, fixup_type: FixupType) -> u64 {
    unsafe { idalib_get_fixup_value(ea.into(), u16::from(fixup_type)) }
}

/// Calculate size of fixup in bytes.
pub fn calc_fixup_size(fixup_type: FixupType) -> i32 {
    unsafe { idalib_calc_fixup_size(u16::from(fixup_type)).0 }
}

/// Get fixup description.
pub fn get_fixup_desc(source: Address) -> Option<String> {
    let desc = unsafe { idalib_get_fixup_desc(source.into()) };
    if desc.is_empty() { None } else { Some(desc) }
}

/// Check if fixup type is custom.
pub fn is_fixup_custom(fixup_type: FixupType) -> bool {
    unsafe { idalib_is_fixup_custom(u16::from(fixup_type)) }
}

/// Iterator over all fixups in the database.
pub struct FixupIter {
    current: Option<Address>,
}

impl FixupIter {
    pub fn new() -> Self {
        Self {
            current: get_first_fixup_ea(),
        }
    }
}

impl Default for FixupIter {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for FixupIter {
    type Item = Fixup;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current?;
        let fixup = get_fixup(current);
        self.current = get_next_fixup_ea(current);
        fixup
    }
}
