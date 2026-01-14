//! Disassembly line generation.
//!
//! This module provides functions to generate disassembly text and
//! work with anterior/posterior lines.

use std::ffi::CString;

use autocxx::prelude::*;

use crate::Address;
use crate::ffi::lines as ffi_lines;
use crate::ffi::lines::*;

/// Disassembly generation flags.
pub mod flags {
    use super::ffi_lines;
    /// Generate a disassembly line as if there is an instruction at the address.
    pub const FORCE_CODE: i32 = ffi_lines::flags::GENDSM_FORCE_CODE;
    /// If the instruction consists of several lines, produce all of them.
    pub const MULTI_LINE: i32 = ffi_lines::flags::GENDSM_MULTI_LINE;
    /// Remove color tags from the output buffer.
    pub const REMOVE_TAGS: i32 = ffi_lines::flags::GENDSM_REMOVE_TAGS;
    /// Display hidden objects.
    pub const UNHIDE: i32 = ffi_lines::flags::GENDSM_UNHIDE;
}

/// Extra lines constants.
pub mod extra {
    use super::ffi_lines;
    /// Anterior line starting number.
    pub const E_PREV: i32 = ffi_lines::extra::E_PREV;
    /// Posterior line starting number.
    pub const E_NEXT: i32 = ffi_lines::extra::E_NEXT;
}

/// Generate one line of disassembly.
///
/// This function generates one-line descriptions of addresses for lists, etc.
/// It discards all "non-interesting" lines.
pub fn generate_disasm_line(ea: Address, flags: i32) -> Option<String> {
    let line = unsafe { idalib_generate_disasm_line(ea.into(), c_int(flags)) };
    if line.is_empty() { None } else { Some(line) }
}

/// Generate one line of disassembly without color tags.
pub fn generate_disasm_line_no_tags(ea: Address) -> Option<String> {
    let line = unsafe { idalib_generate_disasm_line_no_tags(ea.into()) };
    if line.is_empty() { None } else { Some(line) }
}

/// Generate multiple disassembly lines.
///
/// Returns the lines and the number of generated lines.
pub fn generate_disassembly(ea: Address, maxlines: i32) -> Vec<String> {
    let mut out = Vec::new();
    unsafe { idalib_generate_disassembly(ea.into(), c_int(maxlines), &mut out) };
    out
}

/// Remove color escape sequences from a string.
pub fn tag_remove(line: &str) -> Option<String> {
    let c_line = CString::new(line).ok()?;
    let result = unsafe { idalib_tag_remove(c_line.as_ptr()) };
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Calculate length of a colored string in unicode codepoints.
pub fn tag_strlen(line: &str) -> Option<i64> {
    let c_line = CString::new(line).ok()?;
    let len = unsafe { idalib_tag_strlen(c_line.as_ptr()) };
    if len < 0 { None } else { Some(len) }
}

/// Add anterior/posterior non-comment line.
///
/// # Arguments
/// * `ea` - Linear address
/// * `is_prev` - If true, add anterior line; otherwise add posterior line
/// * `line` - Line text
pub fn add_extra_line(ea: Address, is_prev: bool, line: &str) -> bool {
    let c_line = match CString::new(line) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_add_extra_line(ea.into(), is_prev, c_line.as_ptr()) }
}

/// Add anterior/posterior comment line.
///
/// # Arguments
/// * `ea` - Linear address
/// * `is_prev` - If true, add anterior line; otherwise add posterior line
/// * `cmt` - Comment text (without comment characters)
pub fn add_extra_cmt(ea: Address, is_prev: bool, cmt: &str) -> bool {
    let c_cmt = match CString::new(cmt) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_add_extra_cmt(ea.into(), is_prev, c_cmt.as_ptr()) }
}

/// Add anterior comment line at the start of program.
pub fn add_pgm_cmt(cmt: &str) -> bool {
    let c_cmt = match CString::new(cmt) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_add_pgm_cmt(c_cmt.as_ptr()) }
}

/// Get extra comment at the specified address.
///
/// # Arguments
/// * `ea` - Linear address
/// * `n` - Line number (E_PREV + index for anterior, E_NEXT + index for posterior)
pub fn get_extra_cmt(ea: Address, n: i32) -> Option<String> {
    let cmt = unsafe { idalib_get_extra_cmt(ea.into(), c_int(n)) };
    if cmt.is_empty() { None } else { Some(cmt) }
}

/// Delete extra comment at the specified address.
pub fn del_extra_cmt(ea: Address, n: i32) -> bool {
    unsafe { idalib_del_extra_cmt(ea.into(), c_int(n)) }
}

/// Delete all extra comments at the specified address.
pub fn delete_extra_cmts(ea: Address, n: i32) {
    unsafe { idalib_delete_extra_cmts(ea.into(), c_int(n)) }
}

/// Mark a range of addresses as belonging to a source file.
pub fn add_sourcefile(ea1: Address, ea2: Address, filename: &str) -> bool {
    let c_filename = match CString::new(filename) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_add_sourcefile(ea1.into(), ea2.into(), c_filename.as_ptr()) }
}

/// Get name of source file occupying the given address.
pub fn get_sourcefile(ea: Address) -> Option<String> {
    let name = unsafe { idalib_get_sourcefile(ea.into()) };
    if name.is_empty() { None } else { Some(name) }
}

/// Delete information about the source file at the given address.
pub fn del_sourcefile(ea: Address) -> bool {
    unsafe { idalib_del_sourcefile(ea.into()) }
}

/// Get prefix color for line at the given address.
pub fn calc_prefix_color(ea: Address) -> u8 {
    unsafe { idalib_calc_prefix_color(ea.into()) }
}

/// Get background color (RGB) for line at the given address.
pub fn calc_bg_color(ea: Address) -> u32 {
    unsafe { idalib_calc_bg_color(ea.into()) }
}

/// Iterator over anterior lines at an address.
pub struct AnteriorLinesIter {
    ea: Address,
    index: i32,
}

impl AnteriorLinesIter {
    pub fn new(ea: Address) -> Self {
        Self {
            ea,
            index: extra::E_PREV,
        }
    }
}

impl Iterator for AnteriorLinesIter {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        let line = get_extra_cmt(self.ea, self.index)?;
        self.index += 1;
        Some(line)
    }
}

/// Iterator over posterior lines at an address.
pub struct PosteriorLinesIter {
    ea: Address,
    index: i32,
}

impl PosteriorLinesIter {
    pub fn new(ea: Address) -> Self {
        Self {
            ea,
            index: extra::E_NEXT,
        }
    }
}

impl Iterator for PosteriorLinesIter {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        let line = get_extra_cmt(self.ea, self.index)?;
        self.index += 1;
        Some(line)
    }
}
