//! Auto-analysis control.
//!
//! This module provides functions to control IDA's auto-analysis engine.

use autocxx::prelude::*;

use crate::Address;
use crate::ffi::BADADDR;
use crate::ffi::auto::*;

/// Auto-analysis queue types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AutoQueueType {
    None = queue::AU_NONE,
    Unknown = queue::AU_UNK,
    Code = queue::AU_CODE,
    Weak = queue::AU_WEAK,
    Proc = queue::AU_PROC,
    Tail = queue::AU_TAIL,
    FuncChunk = queue::AU_FCHUNK,
    Used = queue::AU_USED,
    Used2 = queue::AU_USD2,
    Type = queue::AU_TYPE,
    LibFunc = queue::AU_LIBF,
    LibFunc2 = queue::AU_LBF2,
    LibFunc3 = queue::AU_LBF3,
    LoadSig = queue::AU_CHLB,
    Final = queue::AU_FINAL,
}

/// IDA state indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum IDAState {
    Ready = state::ST_READY,
    Thinking = state::ST_THINK,
    Waiting = state::ST_WAITING,
    Busy = state::ST_WORK,
}

impl From<i32> for IDAState {
    fn from(value: i32) -> Self {
        match value {
            0 => IDAState::Ready,
            1 => IDAState::Thinking,
            2 => IDAState::Waiting,
            3 => IDAState::Busy,
            _ => IDAState::Ready,
        }
    }
}

/// Get current state of autoanalyzer.
pub fn get_auto_state() -> i32 {
    unsafe { idalib_get_auto_state().0 }
}

/// Set current state of autoanalyzer.
/// Returns the previous state.
pub fn set_auto_state(new_state: i32) -> i32 {
    unsafe { idalib_set_auto_state(c_int(new_state)).0 }
}

/// Set IDA state indicator.
/// Returns the old indicator status.
pub fn set_ida_state(st: IDAState) -> IDAState {
    IDAState::from(unsafe { idalib_set_ida_state(c_int(st as i32)).0 })
}

/// Put single address into a queue.
pub fn auto_mark(ea: Address, queue_type: AutoQueueType) {
    unsafe { idalib_auto_mark(ea.into(), c_int(queue_type as i32)) }
}

/// Put range of addresses into a queue.
pub fn auto_mark_range(start: Address, end: Address, queue_type: AutoQueueType) {
    unsafe { idalib_auto_mark_range(start.into(), end.into(), c_int(queue_type as i32)) }
}

/// Remove range of addresses from a queue.
pub fn auto_unmark(start: Address, end: Address, queue_type: AutoQueueType) {
    unsafe { idalib_auto_unmark(start.into(), end.into(), c_int(queue_type as i32)) }
}

/// Plan to perform reanalysis at the specified address.
pub fn plan_ea(ea: Address) {
    unsafe { idalib_plan_ea(ea.into()) }
}

/// Plan to perform reanalysis for the specified range.
pub fn plan_range(start: Address, end: Address) {
    unsafe { idalib_plan_range(start.into(), end.into()) }
}

/// Plan to make code at the specified address.
pub fn auto_make_code(ea: Address) {
    unsafe { idalib_auto_make_code(ea.into()) }
}

/// Plan to make code and function at the specified address.
pub fn auto_make_proc(ea: Address) {
    unsafe { idalib_auto_make_proc(ea.into()) }
}

/// Are all queues empty? (has autoanalysis finished?)
pub fn auto_is_ok() -> bool {
    unsafe { idalib_auto_is_ok() }
}

/// Remove an address range from queues AU_CODE, AU_PROC, AU_USED.
pub fn auto_cancel(ea1: Address, ea2: Address) {
    unsafe { idalib_auto_cancel(ea1.into(), ea2.into()) }
}

/// Analyze the specified range and wait until finished.
/// Returns 1 if OK, 0 if Ctrl-Break was pressed.
pub fn plan_and_wait(ea1: Address, ea2: Address, final_pass: bool) -> i32 {
    unsafe { idalib_plan_and_wait(ea1.into(), ea2.into(), final_pass).0 }
}

/// Process everything in the specified range and return.
/// Returns number of steps made, -1 if user cancelled.
pub fn auto_wait_range(ea1: Address, ea2: Address) -> i64 {
    unsafe { idalib_auto_wait_range(ea1.into(), ea2.into()) }
}

/// Analyze one address in the specified range.
/// Returns true if processed anything.
pub fn auto_make_step(ea1: Address, ea2: Address) -> bool {
    unsafe { idalib_auto_make_step(ea1.into(), ea2.into()) }
}

/// Peek into a queue for an address not lower than low_ea.
/// Does not remove address from the queue.
pub fn peek_auto_queue(low_ea: Address, queue_type: AutoQueueType) -> Option<Address> {
    let addr = unsafe { idalib_peek_auto_queue(low_ea.into(), c_int(queue_type as i32)) };
    if addr == BADADDR {
        None
    } else {
        Some(addr.into())
    }
}

/// Get autoanalyzer state (enabled/disabled).
pub fn is_auto_enabled() -> bool {
    unsafe { idalib_is_auto_enabled() }
}

/// Temporarily enable/disable autoanalyzer.
/// Returns old state.
pub fn enable_auto(enable: bool) -> bool {
    unsafe { idalib_enable_auto(enable) }
}

/// Plan to reanalyze callers of the specified address.
pub fn reanalyze_callers(ea: Address, noret: bool) {
    unsafe { idalib_reanalyze_callers(ea.into(), noret) }
}

/// Delete all analysis info that IDA generated for the given range.
pub fn revert_ida_decisions(ea1: Address, ea2: Address) {
    unsafe { idalib_revert_ida_decisions(ea1.into(), ea2.into()) }
}

/// Plan to apply the callee's type to the calling point.
pub fn auto_apply_type(caller: Address, callee: Address) {
    unsafe { idalib_auto_apply_type(caller.into(), callee.into()) }
}

/// Try to create instruction at the specified address.
/// Returns the length of the instruction or 0.
pub fn auto_recreate_insn(ea: Address) -> i32 {
    unsafe { idalib_auto_recreate_insn(ea.into()).0 }
}

/// Is it allowed to trace stack pointer automatically?
pub fn may_trace_sp() -> bool {
    unsafe { idalib_may_trace_sp() }
}

/// Is it allowed to create stack variables automatically?
pub fn may_create_stkvars() -> bool {
    unsafe { idalib_may_create_stkvars() }
}
