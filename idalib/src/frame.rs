//! Stack frame analysis.
//!
//! This module provides functions to work with function stack frames,
//! stack variables, register variables, and SP change points.

use autocxx::prelude::*;

use crate::Address;
use crate::ffi::frame::*;
use crate::func::Function;

/// Stack frame information for a function.
pub struct Frame<'a> {
    func: &'a Function<'a>,
}

impl<'a> Frame<'a> {
    pub(crate) fn new(func: &'a Function<'a>) -> Self {
        Self { func }
    }

    /// Get the total size of the frame.
    pub fn size(&self) -> u64 {
        unsafe { idalib_get_frame_size(self.func.as_ptr()) }
    }

    /// Get the size of local variables.
    pub fn local_vars_size(&self) -> i64 {
        unsafe { idalib_func_frsize(self.func.as_ptr()) }
    }

    /// Get the size of saved registers.
    pub fn saved_regs_size(&self) -> u16 {
        unsafe { idalib_func_frregs(self.func.as_ptr()) }
    }

    /// Get the frame pointer delta.
    pub fn fp_delta(&self) -> i64 {
        unsafe { idalib_func_fpd(self.func.as_ptr()) }
    }

    /// Get the size of arguments that will be purged.
    pub fn args_size(&self) -> u64 {
        unsafe { idalib_func_argsize(self.func.as_ptr()) }
    }

    /// Get the size of the return address.
    pub fn retsize(&self) -> i32 {
        unsafe { idalib_get_frame_retsize(self.func.as_ptr()).0 }
    }

    /// Get the starting offset of arguments section.
    pub fn args_offset(&self) -> Address {
        unsafe { idalib_frame_off_args(self.func.as_ptr()) }.into()
    }

    /// Get the starting offset of return address section.
    pub fn retaddr_offset(&self) -> Address {
        unsafe { idalib_frame_off_retaddr(self.func.as_ptr()) }.into()
    }

    /// Get the starting offset of saved registers section.
    pub fn savregs_offset(&self) -> Address {
        unsafe { idalib_frame_off_savregs(self.func.as_ptr()) }.into()
    }

    /// Get the starting offset of local variables section.
    pub fn lvars_offset(&self) -> Address {
        unsafe { idalib_frame_off_lvars(self.func.as_ptr()) }.into()
    }

    /// Get the SP difference from the initial value at the given address.
    pub fn get_spd(&self, ea: Address) -> i64 {
        unsafe { idalib_get_spd(self.func.as_ptr() as *mut _, ea.into()) }
    }

    /// Get the effective SP difference at the given address.
    pub fn get_effective_spd(&self, ea: Address) -> i64 {
        unsafe { idalib_get_effective_spd(self.func.as_ptr() as *mut _, ea.into()) }
    }

    /// Get the SP delta at the given address.
    pub fn get_sp_delta(&self, ea: Address) -> i64 {
        unsafe { idalib_get_sp_delta(self.func.as_ptr() as *mut _, ea.into()) }
    }

    /// Build automatic stack variable name.
    pub fn build_stkvar_name(&self, offset: i64) -> Option<String> {
        let name = unsafe { idalib_build_stkvar_name(self.func.as_ptr(), offset) };
        if name.is_empty() { None } else { Some(name) }
    }

    /// Check if there's a register variable definition at the address.
    pub fn has_regvar(&self, ea: Address) -> bool {
        unsafe { idalib_has_regvar(self.func.as_ptr() as *mut _, ea.into()) }
    }
}

/// Frame part ranges
#[derive(Debug, Clone, Copy)]
pub struct FramePartRange {
    pub start: Address,
    pub end: Address,
}

impl<'a> Function<'a> {
    /// Get stack frame information for this function.
    pub fn frame(&self) -> Frame<'_> {
        Frame::new(self)
    }

    /// Get the arguments section range.
    pub fn frame_args_range(&self) -> FramePartRange {
        let mut start = 0u64.into();
        let mut end = 0u64.into();
        unsafe { idalib_get_frame_part_args(self.as_ptr(), &mut start, &mut end) };
        FramePartRange {
            start: start.into(),
            end: end.into(),
        }
    }

    /// Get the return address section range.
    pub fn frame_retaddr_range(&self) -> FramePartRange {
        let mut start = 0u64.into();
        let mut end = 0u64.into();
        unsafe { idalib_get_frame_part_retaddr(self.as_ptr(), &mut start, &mut end) };
        FramePartRange {
            start: start.into(),
            end: end.into(),
        }
    }

    /// Get the saved registers section range.
    pub fn frame_savregs_range(&self) -> FramePartRange {
        let mut start = 0u64.into();
        let mut end = 0u64.into();
        unsafe { idalib_get_frame_part_savregs(self.as_ptr(), &mut start, &mut end) };
        FramePartRange {
            start: start.into(),
            end: end.into(),
        }
    }

    /// Get the local variables section range.
    pub fn frame_lvars_range(&self) -> FramePartRange {
        let mut start = 0u64.into();
        let mut end = 0u64.into();
        unsafe { idalib_get_frame_part_lvars(self.as_ptr(), &mut start, &mut end) };
        FramePartRange {
            start: start.into(),
            end: end.into(),
        }
    }
}

/// Add a user-defined SP register change point.
pub fn add_user_stkpnt(ea: Address, delta: i64) -> bool {
    unsafe { idalib_add_user_stkpnt(ea.into(), delta) }
}

/// Set the number of purged bytes for a function.
pub fn set_purged(ea: Address, nbytes: i32, override_old_value: bool) -> bool {
    unsafe { idalib_set_purged(ea.into(), c_int(nbytes), override_old_value) }
}
