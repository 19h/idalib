//! Hexrays Decompiler Bindings
//!
//! This module provides high-level Rust bindings for the Hexrays decompiler SDK.
//! It allows you to decompile functions, traverse the C-tree AST, access local
//! variables, and work with the microcode representation.
//!
//! # Overview
//!
//! The decompiler produces a C-like AST (ctree) from binary code. The main types are:
//!
//! - [`CFunction`] - A decompiled function containing the AST and metadata
//! - [`CInsn`] - A C statement (if, while, for, block, return, etc.)
//! - [`CExpr`] - A C expression (arithmetic, calls, variables, etc.)
//! - [`LocalVar`] - A local variable in the decompiled function
//! - [`CBlock`] - A block of statements
//! - [`CArgList`] - Function call arguments
//!
//! # Example
//!
//! ```rust,ignore
//! use idalib::idb::IDB;
//!
//! let idb = IDB::open("/path/to/binary")?;
//! if let Some(func) = idb.function_at(0x1000) {
//!     if let Ok(cfunc) = idb.decompile(&func) {
//!         println!("Pseudocode:\n{}", cfunc.pseudocode());
//!         println!("Entry: 0x{:x}", cfunc.entry_ea());
//!         
//!         // Iterate over local variables
//!         for lvar in cfunc.lvars() {
//!             println!("  {} : {}", lvar.name(), lvar.type_str());
//!         }
//!     }
//! }
//! ```

use std::marker::PhantomData;

use autocxx::c_int;

use crate::Address;
use crate::ffi::hexrays::{
    carg_t,
    carglist_iter,
    carglist_t,
    cblock_iter,
    cblock_t,
    cexpr_t,
    cfunc_t,
    cfuncptr_t,
    cinsn_t,
    citem_t,
    idalib_hexrays_carg_formal_type_str,
    // carg_t operations
    idalib_hexrays_carg_is_vararg,
    idalib_hexrays_carglist_at,
    // carglist_t operations
    idalib_hexrays_carglist_count,
    idalib_hexrays_carglist_iter,
    idalib_hexrays_carglist_iter_next,
    // cblock_t operations
    idalib_hexrays_cblock_iter,
    idalib_hexrays_cblock_iter_next,
    idalib_hexrays_cblock_len,
    idalib_hexrays_cexpr_call_args,
    idalib_hexrays_cexpr_equal_effect,
    idalib_hexrays_cexpr_exflags,
    idalib_hexrays_cexpr_helper,
    idalib_hexrays_cexpr_is_call,
    idalib_hexrays_cexpr_is_child_of,
    idalib_hexrays_cexpr_is_cstr,
    idalib_hexrays_cexpr_is_fpop,
    idalib_hexrays_cexpr_is_nice,
    idalib_hexrays_cexpr_is_undef_val,
    idalib_hexrays_cexpr_member_offset,
    idalib_hexrays_cexpr_numval,
    idalib_hexrays_cexpr_obj_ea,
    idalib_hexrays_cexpr_ptrsize,
    idalib_hexrays_cexpr_requires_lvalue,
    idalib_hexrays_cexpr_str,
    idalib_hexrays_cexpr_type_array_size,
    idalib_hexrays_cexpr_type_is_array,
    idalib_hexrays_cexpr_type_is_bool,
    idalib_hexrays_cexpr_type_is_const,
    idalib_hexrays_cexpr_type_is_enum,
    idalib_hexrays_cexpr_type_is_float,
    idalib_hexrays_cexpr_type_is_funcptr,
    idalib_hexrays_cexpr_type_is_ptr,
    idalib_hexrays_cexpr_type_is_pvoid,
    idalib_hexrays_cexpr_type_is_signed,
    idalib_hexrays_cexpr_type_is_struct,
    idalib_hexrays_cexpr_type_is_union,
    idalib_hexrays_cexpr_type_is_unsigned,
    idalib_hexrays_cexpr_type_is_void,
    idalib_hexrays_cexpr_type_is_volatile,
    idalib_hexrays_cexpr_type_pointed_str,
    idalib_hexrays_cexpr_type_ptr_depth,
    idalib_hexrays_cexpr_type_size,
    // cexpr_t operations
    idalib_hexrays_cexpr_type_str,
    idalib_hexrays_cexpr_var_idx,
    idalib_hexrays_cexpr_x,
    idalib_hexrays_cexpr_y,
    idalib_hexrays_cexpr_z,
    idalib_hexrays_cfunc_argidx_at,
    idalib_hexrays_cfunc_argidx_count,
    idalib_hexrays_cfunc_boundaries_count,
    idalib_hexrays_cfunc_del_orphan_cmts,
    idalib_hexrays_cfunc_eamap_count,
    // cfunc_t operations
    idalib_hexrays_cfunc_entry_ea,
    idalib_hexrays_cfunc_find_by_ea,
    idalib_hexrays_cfunc_find_label,
    idalib_hexrays_cfunc_find_lvar_by_name,
    // Tree navigation
    idalib_hexrays_cfunc_find_parent_of,
    idalib_hexrays_cfunc_has_orphan_cmts,
    idalib_hexrays_cfunc_hdrlines,
    // lvar modifications
    idalib_hexrays_cfunc_lvar_at,
    idalib_hexrays_cfunc_lvars_count,
    idalib_hexrays_cfunc_lvars_iter,
    idalib_hexrays_cfunc_maturity,
    idalib_hexrays_cfunc_mba,
    idalib_hexrays_cfunc_print_dcl,
    idalib_hexrays_cfunc_pseudocode,
    idalib_hexrays_cfunc_pseudocode_line_at,
    // Pseudocode lines
    idalib_hexrays_cfunc_pseudocode_line_count,
    idalib_hexrays_cfunc_pseudocode_line_tagged_at,
    idalib_hexrays_cfunc_refresh,
    idalib_hexrays_cfunc_remove_unused_labels,
    idalib_hexrays_cfunc_save_user_cmts,
    idalib_hexrays_cfunc_save_user_iflags,
    idalib_hexrays_cfunc_save_user_labels,
    idalib_hexrays_cfunc_save_user_numforms,
    idalib_hexrays_cfunc_save_user_unions,
    idalib_hexrays_cfunc_stkoff_delta,
    idalib_hexrays_cfunc_type_str,
    idalib_hexrays_cfunc_warning_at,
    idalib_hexrays_cfunc_warning_ea_at,
    idalib_hexrays_cfunc_warnings_count,
    // Basic decompilation
    idalib_hexrays_cfuncptr_inner,
    // cinsn_t operations
    idalib_hexrays_cinsn_cblock,
    idalib_hexrays_cinsn_cexpr,
    // cinsn_t additional
    idalib_hexrays_cinsn_contains_expr,
    idalib_hexrays_cinsn_contains_free_break,
    idalib_hexrays_cinsn_contains_free_continue,
    idalib_hexrays_cinsn_do_body,
    idalib_hexrays_cinsn_do_cond,
    idalib_hexrays_cinsn_for_body,
    idalib_hexrays_cinsn_for_cond,
    idalib_hexrays_cinsn_for_init,
    idalib_hexrays_cinsn_for_step,
    idalib_hexrays_cinsn_goto_label,
    idalib_hexrays_cinsn_if_cond,
    idalib_hexrays_cinsn_if_else,
    idalib_hexrays_cinsn_if_then,
    idalib_hexrays_cinsn_is_ordinary_flow,
    idalib_hexrays_cinsn_return_expr,
    idalib_hexrays_cinsn_switch_case_body,
    idalib_hexrays_cinsn_switch_case_value_at,
    idalib_hexrays_cinsn_switch_case_values_count,
    idalib_hexrays_cinsn_switch_cases_count,
    idalib_hexrays_cinsn_switch_expr,
    idalib_hexrays_cinsn_throw_expr,
    idalib_hexrays_cinsn_try_first_stmt,
    idalib_hexrays_cinsn_while_body,
    idalib_hexrays_cinsn_while_cond,
    idalib_hexrays_cit_asm,
    idalib_hexrays_cit_block,
    idalib_hexrays_cit_break,
    idalib_hexrays_cit_continue,
    idalib_hexrays_cit_do,
    idalib_hexrays_cit_empty,
    idalib_hexrays_cit_expr,
    idalib_hexrays_cit_for,
    idalib_hexrays_cit_goto,
    idalib_hexrays_cit_if,
    idalib_hexrays_cit_return,
    idalib_hexrays_cit_switch,
    idalib_hexrays_cit_throw,
    idalib_hexrays_cit_try,
    idalib_hexrays_cit_while,
    idalib_hexrays_citem_contains_label,
    // citem_t operations
    idalib_hexrays_citem_ea,
    idalib_hexrays_citem_index_in_parent,
    idalib_hexrays_citem_is_expr,
    idalib_hexrays_citem_label_num,
    idalib_hexrays_citem_op,
    idalib_hexrays_citem_print,
    idalib_hexrays_clear_cached_cfuncs,
    idalib_hexrays_cot_add,
    idalib_hexrays_cot_asg,
    idalib_hexrays_cot_asgadd,
    idalib_hexrays_cot_asgband,
    idalib_hexrays_cot_asgbor,
    idalib_hexrays_cot_asgmul,
    idalib_hexrays_cot_asgsdiv,
    idalib_hexrays_cot_asgshl,
    idalib_hexrays_cot_asgsmod,
    idalib_hexrays_cot_asgsshr,
    idalib_hexrays_cot_asgsub,
    idalib_hexrays_cot_asgudiv,
    idalib_hexrays_cot_asgumod,
    idalib_hexrays_cot_asgushr,
    idalib_hexrays_cot_asgxor,
    idalib_hexrays_cot_band,
    idalib_hexrays_cot_bnot,
    idalib_hexrays_cot_bor,
    idalib_hexrays_cot_call,
    idalib_hexrays_cot_cast,
    idalib_hexrays_cot_comma,
    // ctype constants
    idalib_hexrays_cot_empty,
    idalib_hexrays_cot_eq,
    idalib_hexrays_cot_fadd,
    idalib_hexrays_cot_fdiv,
    idalib_hexrays_cot_fmul,
    idalib_hexrays_cot_fneg,
    idalib_hexrays_cot_fnum,
    idalib_hexrays_cot_fsub,
    idalib_hexrays_cot_helper,
    idalib_hexrays_cot_idx,
    idalib_hexrays_cot_insn,
    idalib_hexrays_cot_land,
    idalib_hexrays_cot_last,
    idalib_hexrays_cot_lnot,
    idalib_hexrays_cot_lor,
    idalib_hexrays_cot_memptr,
    idalib_hexrays_cot_memref,
    idalib_hexrays_cot_mul,
    idalib_hexrays_cot_ne,
    idalib_hexrays_cot_neg,
    idalib_hexrays_cot_num,
    idalib_hexrays_cot_obj,
    idalib_hexrays_cot_postdec,
    idalib_hexrays_cot_postinc,
    idalib_hexrays_cot_predec,
    idalib_hexrays_cot_preinc,
    idalib_hexrays_cot_ptr,
    idalib_hexrays_cot_ref,
    idalib_hexrays_cot_sdiv,
    idalib_hexrays_cot_sge,
    idalib_hexrays_cot_sgt,
    idalib_hexrays_cot_shl,
    idalib_hexrays_cot_sizeof,
    idalib_hexrays_cot_sle,
    idalib_hexrays_cot_slt,
    idalib_hexrays_cot_smod,
    idalib_hexrays_cot_sshr,
    idalib_hexrays_cot_str,
    idalib_hexrays_cot_sub,
    idalib_hexrays_cot_tern,
    idalib_hexrays_cot_type,
    idalib_hexrays_cot_udiv,
    idalib_hexrays_cot_uge,
    idalib_hexrays_cot_ugt,
    idalib_hexrays_cot_ule,
    idalib_hexrays_cot_ult,
    idalib_hexrays_cot_umod,
    idalib_hexrays_cot_ushr,
    idalib_hexrays_cot_var,
    idalib_hexrays_cot_xor,
    // Try/catch operations
    idalib_hexrays_ctry_catch_at,
    idalib_hexrays_ctry_catch_expr_count,
    idalib_hexrays_ctry_catch_is_catch_all,
    idalib_hexrays_ctry_catch_obj_expr,
    idalib_hexrays_ctry_catches_count,
    idalib_hexrays_ctype_name,
    idalib_hexrays_decomp_all_blks,
    idalib_hexrays_decomp_no_cache,
    idalib_hexrays_decomp_no_frame,
    // Decompilation flags
    idalib_hexrays_decomp_no_wait,
    idalib_hexrays_decomp_warnings,
    // merror helpers
    idalib_hexrays_get_merror_desc,
    idalib_hexrays_get_signed_mcode,
    idalib_hexrays_get_unsigned_mcode,
    idalib_hexrays_has_cached_cfunc,
    // Callback infrastructure
    idalib_hexrays_has_callback,
    idalib_hexrays_hxe_build_callinfo,
    idalib_hexrays_hxe_calls_done,
    idalib_hexrays_hxe_combine,
    idalib_hexrays_hxe_flowchart,
    idalib_hexrays_hxe_func_printed,
    idalib_hexrays_hxe_glbopt,
    idalib_hexrays_hxe_interr,
    idalib_hexrays_hxe_locopt,
    idalib_hexrays_hxe_maturity,
    idalib_hexrays_hxe_microcode,
    idalib_hexrays_hxe_prealloc,
    idalib_hexrays_hxe_preoptimized,
    idalib_hexrays_hxe_print_func,
    idalib_hexrays_hxe_prolog,
    idalib_hexrays_hxe_resolve_stkaddrs,
    idalib_hexrays_hxe_stkpnts,
    idalib_hexrays_hxe_structural,
    idalib_hexrays_install_callback,
    idalib_hexrays_is_assignment_op,
    idalib_hexrays_is_binary_op,
    idalib_hexrays_is_commutative_op,
    idalib_hexrays_is_loop_op,
    idalib_hexrays_is_lvalue_op,
    idalib_hexrays_is_mcode_propagatable,
    idalib_hexrays_is_relational_op,
    idalib_hexrays_is_unary_op,
    idalib_hexrays_lvar_cmt,
    idalib_hexrays_lvar_defblk,
    idalib_hexrays_lvar_defea,
    idalib_hexrays_lvar_get_reg,
    idalib_hexrays_lvar_get_stkoff,
    idalib_hexrays_lvar_has_nice_name,
    idalib_hexrays_lvar_has_user_name,
    idalib_hexrays_lvar_has_user_type,
    idalib_hexrays_lvar_is_arg,
    idalib_hexrays_lvar_is_fake,
    idalib_hexrays_lvar_is_floating,
    idalib_hexrays_lvar_is_overlapped,
    idalib_hexrays_lvar_is_reg_var,
    idalib_hexrays_lvar_is_result,
    idalib_hexrays_lvar_is_stk_var,
    idalib_hexrays_lvar_is_thisarg,
    idalib_hexrays_lvar_is_typed,
    idalib_hexrays_lvar_is_used,
    idalib_hexrays_lvar_is_used_byref,
    // lvar_t operations
    idalib_hexrays_lvar_name,
    idalib_hexrays_lvar_set_cmt,
    idalib_hexrays_lvar_set_name,
    idalib_hexrays_lvar_set_type,
    idalib_hexrays_lvar_type_str,
    idalib_hexrays_lvar_width,
    idalib_hexrays_lvars_iter_next,
    // Cache management
    idalib_hexrays_mark_cfunc_dirty,
    idalib_hexrays_mba_argidx_size,
    idalib_hexrays_mba_entry_ea,
    idalib_hexrays_mba_final_maturity,
    idalib_hexrays_mba_first_epilog_ea,
    idalib_hexrays_mba_flags,
    idalib_hexrays_mba_get_mblock,
    // New mba flags
    idalib_hexrays_mba_has_calls,
    idalib_hexrays_mba_has_glbopt,
    idalib_hexrays_mba_has_passregs,
    idalib_hexrays_mba_is_cmnstk,
    idalib_hexrays_mba_is_pattern,
    idalib_hexrays_mba_is_short,
    idalib_hexrays_mba_is_thunk,
    idalib_hexrays_mba_maturity,
    idalib_hexrays_mba_minea,
    // Microcode operations
    idalib_hexrays_mba_qty,
    idalib_hexrays_mba_returns_float,
    idalib_hexrays_mba_stacksize,
    idalib_hexrays_mblock_end,
    idalib_hexrays_mblock_flags,
    idalib_hexrays_mblock_head,
    idalib_hexrays_mblock_insn_count,
    idalib_hexrays_mblock_is_branch,
    // New mblock predicates
    idalib_hexrays_mblock_is_call_block,
    idalib_hexrays_mblock_is_empty,
    idalib_hexrays_mblock_is_fake,
    idalib_hexrays_mblock_is_goto_target,
    idalib_hexrays_mblock_is_noret,
    idalib_hexrays_mblock_is_nway,
    idalib_hexrays_mblock_is_simple_goto_block,
    idalib_hexrays_mblock_is_simple_jcnd_block,
    idalib_hexrays_mblock_is_unknown_call,
    idalib_hexrays_mblock_npred,
    idalib_hexrays_mblock_nsucc,
    idalib_hexrays_mblock_pred,
    idalib_hexrays_mblock_serial,
    idalib_hexrays_mblock_start,
    idalib_hexrays_mblock_succ,
    idalib_hexrays_mblock_tail,
    idalib_hexrays_mblock_type,
    // mcode_t helpers
    idalib_hexrays_mcode_category,
    idalib_hexrays_mcode_is_arithmetic,
    idalib_hexrays_mcode_is_bitwise,
    idalib_hexrays_mcode_is_call,
    idalib_hexrays_mcode_is_comparison,
    idalib_hexrays_mcode_is_fpu,
    idalib_hexrays_mcode_is_jcc,
    idalib_hexrays_mcode_is_jump,
    idalib_hexrays_mcode_is_ret,
    idalib_hexrays_mcode_is_set,
    idalib_hexrays_mcode_modifies_d,
    idalib_hexrays_mcode_modifies_mem,
    idalib_hexrays_mcode_name,
    idalib_hexrays_mcode_reads_mem,
    idalib_hexrays_minsn_d,
    idalib_hexrays_minsn_dstr,
    idalib_hexrays_minsn_ea,
    idalib_hexrays_minsn_find_call,
    idalib_hexrays_minsn_iprops,
    idalib_hexrays_minsn_is_assert,
    idalib_hexrays_minsn_is_call,
    idalib_hexrays_minsn_is_cleaning_pop,
    idalib_hexrays_minsn_is_combined,
    idalib_hexrays_minsn_is_cond,
    idalib_hexrays_minsn_is_farcall,
    idalib_hexrays_minsn_is_fpinsn,
    idalib_hexrays_minsn_is_jump,
    idalib_hexrays_minsn_is_multimov,
    idalib_hexrays_minsn_is_persistent,
    idalib_hexrays_minsn_is_propagatable,
    // New minsn predicates
    idalib_hexrays_minsn_is_tailcall,
    idalib_hexrays_minsn_is_unknown_call,
    idalib_hexrays_minsn_is_wild_match,
    // minsn_t additional operations
    idalib_hexrays_minsn_l,
    idalib_hexrays_minsn_modifies_d,
    idalib_hexrays_minsn_next,
    idalib_hexrays_minsn_nexti,
    idalib_hexrays_minsn_opcode,
    idalib_hexrays_minsn_prev,
    idalib_hexrays_minsn_previ,
    idalib_hexrays_minsn_r,
    idalib_hexrays_minsn_was_noret_icall,
    idalib_hexrays_mop_S,
    idalib_hexrays_mop_a,
    idalib_hexrays_mop_addr_target,
    idalib_hexrays_mop_b,
    idalib_hexrays_mop_c,
    idalib_hexrays_mop_d as idalib_hexrays_mop_d_const,
    idalib_hexrays_mop_dstr,
    idalib_hexrays_mop_f,
    idalib_hexrays_mop_fn,
    idalib_hexrays_mop_glbaddr,
    idalib_hexrays_mop_h,
    idalib_hexrays_mop_insn,
    idalib_hexrays_mop_is_addr,
    idalib_hexrays_mop_is_glb,
    idalib_hexrays_mop_is_insn,
    idalib_hexrays_mop_is_lvar,
    idalib_hexrays_mop_is_number,
    idalib_hexrays_mop_is_reg,
    idalib_hexrays_mop_is_stk,
    idalib_hexrays_mop_l,
    idalib_hexrays_mop_lvar_idx,
    idalib_hexrays_mop_n,
    idalib_hexrays_mop_nnn_value,
    idalib_hexrays_mop_p,
    idalib_hexrays_mop_r,
    idalib_hexrays_mop_reg,
    idalib_hexrays_mop_sc,
    idalib_hexrays_mop_size,
    idalib_hexrays_mop_stkoff,
    idalib_hexrays_mop_str as idalib_hexrays_mop_str_const,
    // mop_t operations
    idalib_hexrays_mop_type,
    idalib_hexrays_mop_v,
    // mop_t type constants
    idalib_hexrays_mop_z,
    idalib_hexrays_must_mcode_close_block,
    // New mcode relation helpers
    idalib_hexrays_negate_mcode_relation,
    // Operator helpers
    idalib_hexrays_negated_relation,
    idalib_hexrays_remove_callback,
    idalib_hexrays_swap_mcode_relation,
    idalib_hexrays_swapped_relation,
    // Types
    lvar_t,
    lvars_iter,
    mba_t,
    mblock_t,
    minsn_t,
    mop_t,
};
use crate::idb::IDB;

pub use crate::ffi::hexrays::{HexRaysError, HexRaysErrorCode};

// ============================================================================
// C-tree type constants
// ============================================================================

/// C-tree item types for expressions and statements.
///
/// Use these constants to identify what kind of node a [`CItem`] represents.
pub mod ctype {
    //! C-tree type constants.
    //!
    //! Expression types start with `COT_` and statement types start with `CIT_`.

    use super::*;

    // Expression types (cot_*)
    /// Empty expression
    pub fn cot_empty() -> i32 {
        unsafe { idalib_hexrays_cot_empty() }.into()
    }
    /// Comma operator: x, y
    pub fn cot_comma() -> i32 {
        unsafe { idalib_hexrays_cot_comma() }.into()
    }
    /// Assignment: x = y
    pub fn cot_asg() -> i32 {
        unsafe { idalib_hexrays_cot_asg() }.into()
    }
    /// Assignment with bitwise or: x |= y
    pub fn cot_asgbor() -> i32 {
        unsafe { idalib_hexrays_cot_asgbor() }.into()
    }
    /// Assignment with xor: x ^= y
    pub fn cot_asgxor() -> i32 {
        unsafe { idalib_hexrays_cot_asgxor() }.into()
    }
    /// Assignment with bitwise and: x &= y
    pub fn cot_asgband() -> i32 {
        unsafe { idalib_hexrays_cot_asgband() }.into()
    }
    /// Assignment with add: x += y
    pub fn cot_asgadd() -> i32 {
        unsafe { idalib_hexrays_cot_asgadd() }.into()
    }
    /// Assignment with sub: x -= y
    pub fn cot_asgsub() -> i32 {
        unsafe { idalib_hexrays_cot_asgsub() }.into()
    }
    /// Assignment with mul: x *= y
    pub fn cot_asgmul() -> i32 {
        unsafe { idalib_hexrays_cot_asgmul() }.into()
    }
    /// Assignment with signed shift right: x >>= y
    pub fn cot_asgsshr() -> i32 {
        unsafe { idalib_hexrays_cot_asgsshr() }.into()
    }
    /// Assignment with unsigned shift right: x >>= y
    pub fn cot_asgushr() -> i32 {
        unsafe { idalib_hexrays_cot_asgushr() }.into()
    }
    /// Assignment with shift left: x <<= y
    pub fn cot_asgshl() -> i32 {
        unsafe { idalib_hexrays_cot_asgshl() }.into()
    }
    /// Assignment with signed div: x /= y
    pub fn cot_asgsdiv() -> i32 {
        unsafe { idalib_hexrays_cot_asgsdiv() }.into()
    }
    /// Assignment with unsigned div: x /= y
    pub fn cot_asgudiv() -> i32 {
        unsafe { idalib_hexrays_cot_asgudiv() }.into()
    }
    /// Assignment with signed mod: x %= y
    pub fn cot_asgsmod() -> i32 {
        unsafe { idalib_hexrays_cot_asgsmod() }.into()
    }
    /// Assignment with unsigned mod: x %= y
    pub fn cot_asgumod() -> i32 {
        unsafe { idalib_hexrays_cot_asgumod() }.into()
    }
    /// Ternary operator: x ? y : z
    pub fn cot_tern() -> i32 {
        unsafe { idalib_hexrays_cot_tern() }.into()
    }
    /// Logical or: x || y
    pub fn cot_lor() -> i32 {
        unsafe { idalib_hexrays_cot_lor() }.into()
    }
    /// Logical and: x && y
    pub fn cot_land() -> i32 {
        unsafe { idalib_hexrays_cot_land() }.into()
    }
    /// Bitwise or: x | y
    pub fn cot_bor() -> i32 {
        unsafe { idalib_hexrays_cot_bor() }.into()
    }
    /// Bitwise xor: x ^ y
    pub fn cot_xor() -> i32 {
        unsafe { idalib_hexrays_cot_xor() }.into()
    }
    /// Bitwise and: x & y
    pub fn cot_band() -> i32 {
        unsafe { idalib_hexrays_cot_band() }.into()
    }
    /// Equal: x == y
    pub fn cot_eq() -> i32 {
        unsafe { idalib_hexrays_cot_eq() }.into()
    }
    /// Not equal: x != y
    pub fn cot_ne() -> i32 {
        unsafe { idalib_hexrays_cot_ne() }.into()
    }
    /// Signed greater or equal: x >= y
    pub fn cot_sge() -> i32 {
        unsafe { idalib_hexrays_cot_sge() }.into()
    }
    /// Unsigned greater or equal: x >= y
    pub fn cot_uge() -> i32 {
        unsafe { idalib_hexrays_cot_uge() }.into()
    }
    /// Signed less or equal: x <= y
    pub fn cot_sle() -> i32 {
        unsafe { idalib_hexrays_cot_sle() }.into()
    }
    /// Unsigned less or equal: x <= y
    pub fn cot_ule() -> i32 {
        unsafe { idalib_hexrays_cot_ule() }.into()
    }
    /// Signed greater than: x > y
    pub fn cot_sgt() -> i32 {
        unsafe { idalib_hexrays_cot_sgt() }.into()
    }
    /// Unsigned greater than: x > y
    pub fn cot_ugt() -> i32 {
        unsafe { idalib_hexrays_cot_ugt() }.into()
    }
    /// Signed less than: x < y
    pub fn cot_slt() -> i32 {
        unsafe { idalib_hexrays_cot_slt() }.into()
    }
    /// Unsigned less than: x < y
    pub fn cot_ult() -> i32 {
        unsafe { idalib_hexrays_cot_ult() }.into()
    }
    /// Signed shift right: x >> y
    pub fn cot_sshr() -> i32 {
        unsafe { idalib_hexrays_cot_sshr() }.into()
    }
    /// Unsigned shift right: x >> y
    pub fn cot_ushr() -> i32 {
        unsafe { idalib_hexrays_cot_ushr() }.into()
    }
    /// Shift left: x << y
    pub fn cot_shl() -> i32 {
        unsafe { idalib_hexrays_cot_shl() }.into()
    }
    /// Addition: x + y
    pub fn cot_add() -> i32 {
        unsafe { idalib_hexrays_cot_add() }.into()
    }
    /// Subtraction: x - y
    pub fn cot_sub() -> i32 {
        unsafe { idalib_hexrays_cot_sub() }.into()
    }
    /// Multiplication: x * y
    pub fn cot_mul() -> i32 {
        unsafe { idalib_hexrays_cot_mul() }.into()
    }
    /// Signed division: x / y
    pub fn cot_sdiv() -> i32 {
        unsafe { idalib_hexrays_cot_sdiv() }.into()
    }
    /// Unsigned division: x / y
    pub fn cot_udiv() -> i32 {
        unsafe { idalib_hexrays_cot_udiv() }.into()
    }
    /// Signed modulo: x % y
    pub fn cot_smod() -> i32 {
        unsafe { idalib_hexrays_cot_smod() }.into()
    }
    /// Unsigned modulo: x % y
    pub fn cot_umod() -> i32 {
        unsafe { idalib_hexrays_cot_umod() }.into()
    }
    /// Floating point addition
    pub fn cot_fadd() -> i32 {
        unsafe { idalib_hexrays_cot_fadd() }.into()
    }
    /// Floating point subtraction
    pub fn cot_fsub() -> i32 {
        unsafe { idalib_hexrays_cot_fsub() }.into()
    }
    /// Floating point multiplication
    pub fn cot_fmul() -> i32 {
        unsafe { idalib_hexrays_cot_fmul() }.into()
    }
    /// Floating point division
    pub fn cot_fdiv() -> i32 {
        unsafe { idalib_hexrays_cot_fdiv() }.into()
    }
    /// Floating point negation
    pub fn cot_fneg() -> i32 {
        unsafe { idalib_hexrays_cot_fneg() }.into()
    }
    /// Integer negation: -x
    pub fn cot_neg() -> i32 {
        unsafe { idalib_hexrays_cot_neg() }.into()
    }
    /// Type cast: (type)x
    pub fn cot_cast() -> i32 {
        unsafe { idalib_hexrays_cot_cast() }.into()
    }
    /// Logical not: !x
    pub fn cot_lnot() -> i32 {
        unsafe { idalib_hexrays_cot_lnot() }.into()
    }
    /// Bitwise not: ~x
    pub fn cot_bnot() -> i32 {
        unsafe { idalib_hexrays_cot_bnot() }.into()
    }
    /// Pointer dereference: *x
    pub fn cot_ptr() -> i32 {
        unsafe { idalib_hexrays_cot_ptr() }.into()
    }
    /// Address of: &x
    pub fn cot_ref() -> i32 {
        unsafe { idalib_hexrays_cot_ref() }.into()
    }
    /// Post-increment: x++
    pub fn cot_postinc() -> i32 {
        unsafe { idalib_hexrays_cot_postinc() }.into()
    }
    /// Post-decrement: x--
    pub fn cot_postdec() -> i32 {
        unsafe { idalib_hexrays_cot_postdec() }.into()
    }
    /// Pre-increment: ++x
    pub fn cot_preinc() -> i32 {
        unsafe { idalib_hexrays_cot_preinc() }.into()
    }
    /// Pre-decrement: --x
    pub fn cot_predec() -> i32 {
        unsafe { idalib_hexrays_cot_predec() }.into()
    }
    /// Function call: f(args)
    pub fn cot_call() -> i32 {
        unsafe { idalib_hexrays_cot_call() }.into()
    }
    /// Array indexing: `x[y]`
    pub fn cot_idx() -> i32 {
        unsafe { idalib_hexrays_cot_idx() }.into()
    }
    /// Member reference: x.m
    pub fn cot_memref() -> i32 {
        unsafe { idalib_hexrays_cot_memref() }.into()
    }
    /// Member pointer: x->m
    pub fn cot_memptr() -> i32 {
        unsafe { idalib_hexrays_cot_memptr() }.into()
    }
    /// Numeric constant
    pub fn cot_num() -> i32 {
        unsafe { idalib_hexrays_cot_num() }.into()
    }
    /// Floating point constant
    pub fn cot_fnum() -> i32 {
        unsafe { idalib_hexrays_cot_fnum() }.into()
    }
    /// String constant
    pub fn cot_str() -> i32 {
        unsafe { idalib_hexrays_cot_str() }.into()
    }
    /// Object (global variable)
    pub fn cot_obj() -> i32 {
        unsafe { idalib_hexrays_cot_obj() }.into()
    }
    /// Local variable
    pub fn cot_var() -> i32 {
        unsafe { idalib_hexrays_cot_var() }.into()
    }
    /// Embedded statement in expression
    pub fn cot_insn() -> i32 {
        unsafe { idalib_hexrays_cot_insn() }.into()
    }
    /// sizeof(type)
    pub fn cot_sizeof() -> i32 {
        unsafe { idalib_hexrays_cot_sizeof() }.into()
    }
    /// Helper function (arbitrary name)
    pub fn cot_helper() -> i32 {
        unsafe { idalib_hexrays_cot_helper() }.into()
    }
    /// Type name (in sizeof, etc.)
    pub fn cot_type() -> i32 {
        unsafe { idalib_hexrays_cot_type() }.into()
    }
    /// Last expression type
    pub fn cot_last() -> i32 {
        unsafe { idalib_hexrays_cot_last() }.into()
    }

    // Statement types (cit_*)
    /// Empty statement
    pub fn cit_empty() -> i32 {
        unsafe { idalib_hexrays_cit_empty() }.into()
    }
    /// Block statement: { ... }
    pub fn cit_block() -> i32 {
        unsafe { idalib_hexrays_cit_block() }.into()
    }
    /// Expression statement: expr;
    pub fn cit_expr() -> i32 {
        unsafe { idalib_hexrays_cit_expr() }.into()
    }
    /// If statement
    pub fn cit_if() -> i32 {
        unsafe { idalib_hexrays_cit_if() }.into()
    }
    /// For loop
    pub fn cit_for() -> i32 {
        unsafe { idalib_hexrays_cit_for() }.into()
    }
    /// While loop
    pub fn cit_while() -> i32 {
        unsafe { idalib_hexrays_cit_while() }.into()
    }
    /// Do-while loop
    pub fn cit_do() -> i32 {
        unsafe { idalib_hexrays_cit_do() }.into()
    }
    /// Switch statement
    pub fn cit_switch() -> i32 {
        unsafe { idalib_hexrays_cit_switch() }.into()
    }
    /// Return statement
    pub fn cit_return() -> i32 {
        unsafe { idalib_hexrays_cit_return() }.into()
    }
    /// Goto statement
    pub fn cit_goto() -> i32 {
        unsafe { idalib_hexrays_cit_goto() }.into()
    }
    /// Inline assembly
    pub fn cit_asm() -> i32 {
        unsafe { idalib_hexrays_cit_asm() }.into()
    }
    /// Break statement
    pub fn cit_break() -> i32 {
        unsafe { idalib_hexrays_cit_break() }.into()
    }
    /// Continue statement
    pub fn cit_continue() -> i32 {
        unsafe { idalib_hexrays_cit_continue() }.into()
    }
    /// Throw statement
    pub fn cit_throw() -> i32 {
        unsafe { idalib_hexrays_cit_throw() }.into()
    }
    /// Try statement
    pub fn cit_try() -> i32 {
        unsafe { idalib_hexrays_cit_try() }.into()
    }
}

/// Decompilation flags.
pub mod decomp_flags {
    //! Flags for controlling decompilation behavior.

    use super::*;

    /// Don't wait for decompilation to complete (return immediately).
    pub fn no_wait() -> i32 {
        unsafe { idalib_hexrays_decomp_no_wait() }.into()
    }
    /// Don't use/update the decompilation cache.
    pub fn no_cache() -> i32 {
        unsafe { idalib_hexrays_decomp_no_cache() }.into()
    }
    /// Don't use stack frame information.
    pub fn no_frame() -> i32 {
        unsafe { idalib_hexrays_decomp_no_frame() }.into()
    }
    /// Collect warnings during decompilation.
    pub fn warnings() -> i32 {
        unsafe { idalib_hexrays_decomp_warnings() }.into()
    }
    /// Decompile all basic blocks (not just reachable ones).
    pub fn all_blocks() -> i32 {
        unsafe { idalib_hexrays_decomp_all_blks() }.into()
    }
}

// ============================================================================
// Operator helper functions
// ============================================================================

/// Get the negated form of a relational operator.
///
/// For example, `==` becomes `!=`, `<` becomes `>=`.
pub fn negated_relation(op: i32) -> i32 {
    unsafe { idalib_hexrays_negated_relation(c_int(op)) }.into()
}

/// Get the swapped form of a relational operator.
///
/// For example, `<` becomes `>`, `<=` becomes `>=`.
pub fn swapped_relation(op: i32) -> i32 {
    unsafe { idalib_hexrays_swapped_relation(c_int(op)) }.into()
}

/// Check if an operator is unary (has one operand).
pub fn is_unary_op(op: i32) -> bool {
    unsafe { idalib_hexrays_is_unary_op(c_int(op)) }
}

/// Check if an operator is binary (has two operands).
pub fn is_binary_op(op: i32) -> bool {
    unsafe { idalib_hexrays_is_binary_op(c_int(op)) }
}

/// Check if an operator is relational (comparison).
pub fn is_relational_op(op: i32) -> bool {
    unsafe { idalib_hexrays_is_relational_op(c_int(op)) }
}

/// Check if an operator is an assignment.
pub fn is_assignment_op(op: i32) -> bool {
    unsafe { idalib_hexrays_is_assignment_op(c_int(op)) }
}

/// Check if an operator is commutative (order doesn't matter).
pub fn is_commutative_op(op: i32) -> bool {
    unsafe { idalib_hexrays_is_commutative_op(c_int(op)) }
}

/// Check if an operator produces an lvalue.
pub fn is_lvalue_op(op: i32) -> bool {
    unsafe { idalib_hexrays_is_lvalue_op(c_int(op)) }
}

/// Check if an operator represents a loop.
pub fn is_loop_op(op: i32) -> bool {
    unsafe { idalib_hexrays_is_loop_op(c_int(op)) }
}

/// Get the name of a C-tree type.
pub fn ctype_name(op: i32) -> String {
    unsafe { idalib_hexrays_ctype_name(c_int(op)) }
}

// ============================================================================
// Cache management functions
// ============================================================================

/// Mark a cached decompilation result as dirty.
///
/// This forces redecompilation on the next request.
/// If `close_views` is true, also close any pseudocode views.
pub fn mark_cfunc_dirty(ea: Address, close_views: bool) -> bool {
    unsafe { idalib_hexrays_mark_cfunc_dirty(ea, close_views) }
}

/// Clear all cached decompilation results.
pub fn clear_cached_cfuncs() {
    unsafe { idalib_hexrays_clear_cached_cfuncs() }
}

/// Check if a function has a cached decompilation result.
pub fn has_cached_cfunc(ea: Address) -> bool {
    unsafe { idalib_hexrays_has_cached_cfunc(ea) }
}

// ============================================================================
// CFunction - Decompiled function
// ============================================================================

/// A decompiled function.
///
/// This is the main entry point for working with decompiled code. It contains
/// the C-tree AST, local variables, and various metadata about the function.
///
/// # Example
///
/// ```rust,ignore
/// if let Ok(cfunc) = idb.decompile(&func) {
///     // Get pseudocode
///     println!("{}", cfunc.pseudocode());
///     
///     // Get function entry address
///     println!("Entry: 0x{:x}", cfunc.entry_ea());
///     
///     // Iterate over local variables
///     for lvar in cfunc.lvars() {
///         println!("  {}: {}", lvar.name(), lvar.type_str());
///     }
///     
///     // Access the function body
///     let body = cfunc.body();
///     println!("Body has {} statements", body.len());
/// }
/// ```
pub struct CFunction<'a> {
    ptr: *mut cfunc_t,
    _obj: cxx::UniquePtr<cfuncptr_t>,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> CFunction<'a> {
    pub(crate) fn new(obj: cxx::UniquePtr<cfuncptr_t>) -> Option<Self> {
        let ptr = unsafe { idalib_hexrays_cfuncptr_inner(obj.as_ref().expect("valid pointer")) };

        if ptr.is_null() {
            return None;
        }

        Some(Self {
            ptr,
            _obj: obj,
            _marker: PhantomData,
        })
    }

    fn as_cfunc(&self) -> &cfunc_t {
        unsafe { self.ptr.as_ref().expect("valid pointer") }
    }

    /// Get the function's pseudocode as a string.
    ///
    /// This returns the complete decompiled C code for the function.
    pub fn pseudocode(&self) -> String {
        unsafe { idalib_hexrays_cfunc_pseudocode(self.ptr) }
    }

    /// Get the function's entry address.
    pub fn entry_ea(&self) -> Address {
        unsafe { idalib_hexrays_cfunc_entry_ea(self.ptr) }
    }

    /// Get the function's maturity level.
    ///
    /// Higher values indicate more complete decompilation.
    pub fn maturity(&self) -> i32 {
        unsafe { idalib_hexrays_cfunc_maturity(self.ptr) }.into()
    }

    /// Get the number of header lines (declaration area).
    pub fn header_lines(&self) -> i32 {
        unsafe { idalib_hexrays_cfunc_hdrlines(self.ptr) }.into()
    }

    /// Get the function declaration as a string.
    pub fn declaration(&self) -> String {
        unsafe { idalib_hexrays_cfunc_print_dcl(self.ptr) }
    }

    /// Get the function type as a string.
    pub fn type_str(&self) -> String {
        unsafe { idalib_hexrays_cfunc_type_str(self.ptr) }
    }

    /// Get the stack offset delta.
    pub fn stkoff_delta(&self) -> i64 {
        unsafe { idalib_hexrays_cfunc_stkoff_delta(self.ptr) }
    }

    /// Get the function body as a block.
    pub fn body(&self) -> CBlock<'_> {
        let cf = self.as_cfunc();
        let ptr = unsafe { cf.body.__bindgen_anon_1.cblock };

        CBlock {
            ptr,
            _marker: PhantomData,
        }
    }

    // --- Local variables ---

    /// Get the number of local variables.
    pub fn lvars_count(&self) -> usize {
        unsafe { idalib_hexrays_cfunc_lvars_count(self.ptr) }
    }

    /// Get an iterator over local variables.
    pub fn lvars(&self) -> LocalVarIter<'_> {
        LocalVarIter {
            it: unsafe { idalib_hexrays_cfunc_lvars_iter(self.ptr) },
            _marker: PhantomData,
        }
    }

    // --- Arguments ---

    /// Get the number of function arguments.
    pub fn args_count(&self) -> usize {
        unsafe { idalib_hexrays_cfunc_argidx_count(self.ptr) }
    }

    /// Get the local variable index for argument at position `i`.
    pub fn arg_lvar_idx(&self, i: usize) -> Option<i32> {
        let idx: i32 = unsafe { idalib_hexrays_cfunc_argidx_at(self.ptr, i) }.into();
        if idx >= 0 { Some(idx) } else { None }
    }

    // --- Warnings ---

    /// Get the number of warnings generated during decompilation.
    pub fn warnings_count(&self) -> usize {
        unsafe { idalib_hexrays_cfunc_warnings_count(self.ptr) }
    }

    /// Get a warning message at the given index.
    pub fn warning_at(&self, idx: usize) -> String {
        unsafe { idalib_hexrays_cfunc_warning_at(self.ptr, idx) }
    }

    /// Get the address associated with a warning.
    pub fn warning_ea_at(&self, idx: usize) -> Address {
        unsafe { idalib_hexrays_cfunc_warning_ea_at(self.ptr, idx) }
    }

    /// Get all warnings as a vector of (address, message) pairs.
    pub fn warnings(&self) -> Vec<(Address, String)> {
        let count = self.warnings_count();
        (0..count)
            .map(|i| (self.warning_ea_at(i), self.warning_at(i)))
            .collect()
    }

    // --- Labels and comments ---

    /// Find a label by number in the C-tree.
    pub fn find_label(&self, label: i32) -> Option<CItem<'_>> {
        let ptr = unsafe { idalib_hexrays_cfunc_find_label(self.ptr, c_int(label)) };
        if ptr.is_null() {
            None
        } else {
            Some(CItem {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Check if there are orphan comments (comments without associated items).
    pub fn has_orphan_cmts(&self) -> bool {
        unsafe { idalib_hexrays_cfunc_has_orphan_cmts(self.ptr) }
    }

    /// Delete orphan comments. Returns the number deleted.
    pub fn del_orphan_cmts(&self) -> i32 {
        unsafe { idalib_hexrays_cfunc_del_orphan_cmts(self.ptr) }.into()
    }

    /// Remove unused labels from the C-tree.
    pub fn remove_unused_labels(&self) {
        unsafe { idalib_hexrays_cfunc_remove_unused_labels(self.ptr) }
    }

    // --- Save user modifications ---

    /// Refresh the decompilation.
    pub fn refresh(&self) {
        unsafe { idalib_hexrays_cfunc_refresh(self.ptr) }
    }

    /// Save user-defined labels.
    pub fn save_user_labels(&self) {
        unsafe { idalib_hexrays_cfunc_save_user_labels(self.ptr) }
    }

    /// Save user-defined comments.
    pub fn save_user_cmts(&self) {
        unsafe { idalib_hexrays_cfunc_save_user_cmts(self.ptr) }
    }

    /// Save user-defined number formats.
    pub fn save_user_numforms(&self) {
        unsafe { idalib_hexrays_cfunc_save_user_numforms(self.ptr) }
    }

    /// Save user-defined item flags.
    pub fn save_user_iflags(&self) {
        unsafe { idalib_hexrays_cfunc_save_user_iflags(self.ptr) }
    }

    /// Save user-defined union selections.
    pub fn save_user_unions(&self) {
        unsafe { idalib_hexrays_cfunc_save_user_unions(self.ptr) }
    }

    // --- Tree navigation ---

    /// Find the parent of an item in the C-tree.
    pub fn find_parent_of(&self, item: &CItem<'_>) -> Option<CItem<'_>> {
        let ptr = unsafe { idalib_hexrays_cfunc_find_parent_of(self.ptr, item.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CItem {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Find an item by address in the C-tree.
    pub fn find_by_ea(&self, ea: Address) -> Option<CItem<'_>> {
        let ptr = unsafe { idalib_hexrays_cfunc_find_by_ea(self.ptr, ea) };
        if ptr.is_null() {
            None
        } else {
            Some(CItem {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the index of an item within its parent (if in a block).
    pub fn item_index_in_parent(&self, item: &CItem<'_>) -> Option<i32> {
        let idx: i32 = unsafe { idalib_hexrays_citem_index_in_parent(self.ptr, item.ptr) }.into();
        if idx >= 0 { Some(idx) } else { None }
    }

    // --- Local variable access ---

    /// Get a local variable by index.
    pub fn lvar_at(&self, idx: usize) -> Option<LocalVar<'_>> {
        let ptr = unsafe { idalib_hexrays_cfunc_lvar_at(self.ptr, idx) };
        if ptr.is_null() {
            None
        } else {
            Some(LocalVar {
                ptr,
                cfunc: self.ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Find a local variable by name.
    pub fn find_lvar_by_name(&self, name: &str) -> Option<LocalVar<'_>> {
        let c_name = std::ffi::CString::new(name).ok()?;
        let ptr = unsafe { idalib_hexrays_cfunc_find_lvar_by_name(self.ptr, c_name.as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(LocalVar {
                ptr,
                cfunc: self.ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- Pseudocode line access ---

    /// Get the number of lines in the pseudocode.
    pub fn pseudocode_line_count(&self) -> usize {
        unsafe { idalib_hexrays_cfunc_pseudocode_line_count(self.ptr) }
    }

    /// Get a specific line of pseudocode (without color tags).
    pub fn pseudocode_line_at(&self, idx: usize) -> String {
        unsafe { idalib_hexrays_cfunc_pseudocode_line_at(self.ptr, idx) }
    }

    /// Get a specific line of pseudocode with color tags.
    pub fn pseudocode_line_tagged_at(&self, idx: usize) -> String {
        unsafe { idalib_hexrays_cfunc_pseudocode_line_tagged_at(self.ptr, idx) }
    }

    /// Get the number of instruction boundaries.
    pub fn boundaries_count(&self) -> usize {
        unsafe { idalib_hexrays_cfunc_boundaries_count(self.ptr) }
    }

    /// Get the number of entries in the address map.
    pub fn eamap_count(&self) -> usize {
        unsafe { idalib_hexrays_cfunc_eamap_count(self.ptr) }
    }

    // --- Microcode access ---

    /// Get the microcode array for this function.
    ///
    /// Returns `None` if microcode is not available (e.g., after optimization).
    pub fn mba(&self) -> Option<Mba<'_>> {
        let ptr = unsafe { idalib_hexrays_cfunc_mba(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(Mba {
                ptr,
                _marker: PhantomData,
            })
        }
    }
}

// ============================================================================
// CBlock - Block of statements
// ============================================================================

/// A block of C statements.
///
/// Represents a `{ ... }` block in the decompiled code.
pub struct CBlock<'a> {
    ptr: *mut cblock_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CBlock<'a> {
    /// Get an iterator over statements in the block.
    pub fn iter(&self) -> CBlockIter<'_> {
        CBlockIter {
            it: unsafe { idalib_hexrays_cblock_iter(self.ptr) },
            _marker: PhantomData,
        }
    }

    /// Get the number of statements in the block.
    pub fn len(&self) -> usize {
        unsafe { idalib_hexrays_cblock_len(self.ptr) }
    }

    /// Check if the block is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> IntoIterator for &'a CBlock<'a> {
    type Item = CInsn<'a>;
    type IntoIter = CBlockIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over statements in a block.
pub struct CBlockIter<'a> {
    it: cxx::UniquePtr<cblock_iter>,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Iterator for CBlockIter<'a> {
    type Item = CInsn<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = unsafe { idalib_hexrays_cblock_iter_next(self.it.pin_mut()) };

        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }
}

// ============================================================================
// CItem - Base for CExpr and CInsn
// ============================================================================

/// A C-tree item (base type for expressions and statements).
///
/// This is the common base for [`CExpr`] and [`CInsn`].
pub struct CItem<'a> {
    ptr: *mut citem_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CItem<'a> {
    /// Get the address of the original code that generated this item.
    pub fn ea(&self) -> Address {
        unsafe { idalib_hexrays_citem_ea(self.ptr) }
    }

    /// Get the operation type code.
    ///
    /// Compare with constants in [`ctype`] module.
    pub fn op(&self) -> i32 {
        unsafe { idalib_hexrays_citem_op(self.ptr) }.into()
    }

    /// Check if this item is an expression (as opposed to a statement).
    pub fn is_expr(&self) -> bool {
        unsafe { idalib_hexrays_citem_is_expr(self.ptr) }
    }

    /// Get the label number, or -1 if no label.
    pub fn label_num(&self) -> i32 {
        unsafe { idalib_hexrays_citem_label_num(self.ptr) }.into()
    }

    /// Check if this item or any child contains a specific label.
    pub fn contains_label(&self) -> bool {
        unsafe { idalib_hexrays_citem_contains_label(self.ptr) }
    }

    /// Print this item as a string.
    pub fn print(&self) -> String {
        unsafe { idalib_hexrays_citem_print(self.ptr) }
    }

    /// Get the name of the item's type code.
    pub fn op_name(&self) -> String {
        ctype_name(self.op())
    }

    /// Try to convert to an expression.
    pub fn as_expr(&self) -> Option<CExpr<'a>> {
        if self.is_expr() {
            Some(CExpr {
                ptr: self.ptr as *mut cexpr_t,
                _marker: PhantomData,
            })
        } else {
            None
        }
    }

    /// Try to convert to a statement.
    pub fn as_insn(&self) -> Option<CInsn<'a>> {
        if !self.is_expr() {
            Some(CInsn {
                ptr: self.ptr as *mut cinsn_t,
                _marker: PhantomData,
            })
        } else {
            None
        }
    }
}

// ============================================================================
// CInsn - C statement
// ============================================================================

/// A C statement in the decompiled code.
///
/// Represents statements like `if`, `while`, `for`, `return`, etc.
///
/// # Example
///
/// ```rust,ignore
/// for insn in cfunc.body().iter() {
///     match insn.op() {
///         op if op == ctype::cit_if() => {
///             if let Some(cond) = insn.if_cond() {
///                 println!("if condition: {}", cond.print());
///             }
///         }
///         op if op == ctype::cit_return() => {
///             if let Some(expr) = insn.return_expr() {
///                 println!("return: {}", expr.print());
///             }
///         }
///         _ => {}
///     }
/// }
/// ```
pub struct CInsn<'a> {
    ptr: *mut cinsn_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CInsn<'a> {
    /// Get the address of the original code.
    pub fn ea(&self) -> Address {
        unsafe { idalib_hexrays_citem_ea(self.ptr as *mut citem_t) }
    }

    /// Get the statement type code.
    pub fn op(&self) -> i32 {
        unsafe { idalib_hexrays_citem_op(self.ptr as *mut citem_t) }.into()
    }

    /// Get the label number, or -1 if no label.
    pub fn label_num(&self) -> i32 {
        unsafe { idalib_hexrays_citem_label_num(self.ptr as *mut citem_t) }.into()
    }

    /// Print this statement as a string.
    pub fn print(&self) -> String {
        unsafe { idalib_hexrays_citem_print(self.ptr as *mut citem_t) }
    }

    /// Get the name of the statement type.
    pub fn op_name(&self) -> String {
        ctype_name(self.op())
    }

    /// Check if this is ordinary flow (no jumps).
    pub fn is_ordinary_flow(&self) -> bool {
        unsafe { idalib_hexrays_cinsn_is_ordinary_flow(self.ptr) }
    }

    /// Check if this statement contains a free break.
    pub fn contains_free_break(&self) -> bool {
        unsafe { idalib_hexrays_cinsn_contains_free_break(self.ptr) }
    }

    /// Check if this statement contains a free continue.
    pub fn contains_free_continue(&self) -> bool {
        unsafe { idalib_hexrays_cinsn_contains_free_continue(self.ptr) }
    }

    // --- Block statement ---

    /// Get the block if this is a block statement.
    pub fn cblock(&self) -> Option<CBlock<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_cblock(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CBlock {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- Expression statement ---

    /// Get the expression if this is an expression statement.
    pub fn cexpr(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_cexpr(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- If statement ---

    /// Get the condition of an if statement.
    pub fn if_cond(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_if_cond(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the 'then' branch of an if statement.
    pub fn if_then(&self) -> Option<CInsn<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_if_then(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the 'else' branch of an if statement.
    pub fn if_else(&self) -> Option<CInsn<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_if_else(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- For loop ---

    /// Get the initialization of a for loop.
    pub fn for_init(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_for_init(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the condition of a for loop.
    pub fn for_cond(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_for_cond(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the step expression of a for loop.
    pub fn for_step(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_for_step(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the body of a for loop.
    pub fn for_body(&self) -> Option<CInsn<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_for_body(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- While loop ---

    /// Get the condition of a while loop.
    pub fn while_cond(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_while_cond(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the body of a while loop.
    pub fn while_body(&self) -> Option<CInsn<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_while_body(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- Do-while loop ---

    /// Get the body of a do-while loop.
    pub fn do_body(&self) -> Option<CInsn<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_do_body(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the condition of a do-while loop.
    pub fn do_cond(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_do_cond(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- Switch statement ---

    /// Get the expression of a switch statement.
    pub fn switch_expr(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_switch_expr(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the number of cases in a switch statement.
    pub fn switch_cases_count(&self) -> usize {
        unsafe { idalib_hexrays_cinsn_switch_cases_count(self.ptr) }
    }

    /// Get the number of values for a specific case in a switch statement.
    ///
    /// A single case can have multiple values (e.g., `case 1: case 2: ...`).
    pub fn switch_case_values_count(&self, case_idx: usize) -> usize {
        unsafe { idalib_hexrays_cinsn_switch_case_values_count(self.ptr, case_idx) }
    }

    /// Get a specific value from a switch case.
    ///
    /// # Arguments
    /// * `case_idx` - Index of the case (0..switch_cases_count())
    /// * `value_idx` - Index of the value within the case (0..switch_case_values_count())
    pub fn switch_case_value_at(&self, case_idx: usize, value_idx: usize) -> u64 {
        unsafe { idalib_hexrays_cinsn_switch_case_value_at(self.ptr, case_idx, value_idx) }
    }

    /// Get the body of a switch case.
    ///
    /// Returns the statement(s) to execute for the case.
    pub fn switch_case_body(&self, case_idx: usize) -> Option<CInsn<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_switch_case_body(self.ptr, case_idx) };
        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Iterate over all switch cases with their values and bodies.
    ///
    /// Returns an iterator yielding (case_values, body) pairs.
    pub fn switch_cases(&self) -> impl Iterator<Item = (Vec<u64>, Option<CInsn<'a>>)> + '_ {
        (0..self.switch_cases_count()).map(move |case_idx| {
            let values: Vec<u64> = (0..self.switch_case_values_count(case_idx))
                .map(|val_idx| self.switch_case_value_at(case_idx, val_idx))
                .collect();
            let body = self.switch_case_body(case_idx);
            (values, body)
        })
    }

    // --- Try/catch statement ---

    /// Get the first statement in a try block.
    pub fn try_first_stmt(&self) -> Option<CInsn<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_try_first_stmt(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the number of catch blocks in a try statement.
    pub fn try_catches_count(&self) -> usize {
        unsafe { idalib_hexrays_ctry_catches_count(self.ptr) }
    }

    /// Get a specific catch block from a try statement.
    pub fn try_catch_at(&self, idx: usize) -> Option<CInsn<'a>> {
        let ptr = unsafe { idalib_hexrays_ctry_catch_at(self.ptr, idx) };
        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the number of catch expressions for a catch block.
    pub fn try_catch_expr_count(&self, catch_idx: usize) -> usize {
        unsafe { idalib_hexrays_ctry_catch_expr_count(self.ptr, catch_idx) }
    }

    /// Check if a catch block is a "catch all" (catches everything).
    pub fn try_catch_is_catch_all(&self, catch_idx: usize) -> bool {
        unsafe { idalib_hexrays_ctry_catch_is_catch_all(self.ptr, catch_idx) }
    }

    /// Get the caught object expression for a catch block.
    pub fn try_catch_obj_expr(&self, catch_idx: usize, expr_idx: usize) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_ctry_catch_obj_expr(self.ptr, catch_idx, expr_idx) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- Throw statement ---

    /// Get the expression being thrown.
    pub fn throw_expr(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_throw_expr(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- Additional helpers ---

    /// Check if this statement contains a specific expression.
    pub fn contains_expr(&self, expr: &CExpr<'_>) -> bool {
        unsafe { idalib_hexrays_cinsn_contains_expr(self.ptr, expr.ptr) }
    }

    // --- Return statement ---

    /// Get the expression of a return statement.
    pub fn return_expr(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cinsn_return_expr(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- Goto statement ---

    /// Get the target label of a goto statement.
    pub fn goto_label(&self) -> i32 {
        unsafe { idalib_hexrays_cinsn_goto_label(self.ptr) }.into()
    }
}

// ============================================================================
// CExpr - C expression
// ============================================================================

/// A C expression in the decompiled code.
///
/// Represents expressions like arithmetic operations, function calls,
/// variable references, etc.
///
/// # Example
///
/// ```rust,ignore
/// fn analyze_expr(expr: &CExpr) {
///     let op = expr.op();
///     
///     if op == ctype::cot_call() {
///         // Function call
///         if let Some(args) = expr.call_args() {
///             println!("Call with {} arguments", args.len());
///         }
///     } else if op == ctype::cot_var() {
///         // Local variable reference
///         println!("Variable index: {}", expr.var_idx());
///     } else if op == ctype::cot_num() {
///         // Numeric constant
///         println!("Number: {}", expr.numval());
///     }
/// }
/// ```
pub struct CExpr<'a> {
    ptr: *mut cexpr_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CExpr<'a> {
    /// Get the address of the original code.
    pub fn ea(&self) -> Address {
        unsafe { idalib_hexrays_citem_ea(self.ptr as *mut citem_t) }
    }

    /// Get the expression type code.
    pub fn op(&self) -> i32 {
        unsafe { idalib_hexrays_citem_op(self.ptr as *mut citem_t) }.into()
    }

    /// Get the label number, or -1 if no label.
    pub fn label_num(&self) -> i32 {
        unsafe { idalib_hexrays_citem_label_num(self.ptr as *mut citem_t) }.into()
    }

    /// Print this expression as a string.
    pub fn print(&self) -> String {
        unsafe { idalib_hexrays_citem_print(self.ptr as *mut citem_t) }
    }

    /// Get the name of the expression type.
    pub fn op_name(&self) -> String {
        ctype_name(self.op())
    }

    // --- Type information ---

    /// Get the result type as a string.
    pub fn type_str(&self) -> String {
        unsafe { idalib_hexrays_cexpr_type_str(self.ptr) }
    }

    /// Get the size of the result type in bytes.
    pub fn type_size(&self) -> usize {
        unsafe { idalib_hexrays_cexpr_type_size(self.ptr) }
    }

    /// Check if the result type is a pointer.
    pub fn type_is_ptr(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_ptr(self.ptr) }
    }

    /// Check if the result type is an array.
    pub fn type_is_array(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_array(self.ptr) }
    }

    /// Check if the result type is a struct.
    pub fn type_is_struct(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_struct(self.ptr) }
    }

    /// Check if the result type is a union.
    pub fn type_is_union(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_union(self.ptr) }
    }

    /// Check if the result type is a floating point type.
    pub fn type_is_float(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_float(self.ptr) }
    }

    /// Check if the result type is signed.
    pub fn type_is_signed(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_signed(self.ptr) }
    }

    /// Check if the result type is unsigned.
    pub fn type_is_unsigned(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_unsigned(self.ptr) }
    }

    // --- Operands ---

    /// Get the first operand (x) of a binary/unary expression.
    pub fn x(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cexpr_x(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the second operand (y) of a binary expression.
    pub fn y(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cexpr_y(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the third operand (z) of a ternary expression.
    pub fn z(&self) -> Option<CExpr<'a>> {
        let ptr = unsafe { idalib_hexrays_cexpr_z(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CExpr {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- Specific expression data ---

    /// Get the numeric value (for cot_num).
    pub fn numval(&self) -> u64 {
        unsafe { idalib_hexrays_cexpr_numval(self.ptr) }
    }

    /// Get the object address (for cot_obj).
    pub fn obj_ea(&self) -> Address {
        unsafe { idalib_hexrays_cexpr_obj_ea(self.ptr) }
    }

    /// Get the variable index (for cot_var).
    pub fn var_idx(&self) -> i32 {
        unsafe { idalib_hexrays_cexpr_var_idx(self.ptr) }.into()
    }

    /// Get the string value (for cot_str).
    pub fn string(&self) -> String {
        unsafe { idalib_hexrays_cexpr_str(self.ptr) }
    }

    /// Get the helper name (for cot_helper).
    pub fn helper(&self) -> String {
        unsafe { idalib_hexrays_cexpr_helper(self.ptr) }
    }

    /// Get the member offset (for cot_memref/cot_memptr).
    pub fn member_offset(&self) -> u32 {
        unsafe { idalib_hexrays_cexpr_member_offset(self.ptr) }
    }

    /// Get the pointer size (for cot_ptr/cot_memptr).
    pub fn ptrsize(&self) -> i32 {
        unsafe { idalib_hexrays_cexpr_ptrsize(self.ptr) }.into()
    }

    /// Get the expression flags.
    pub fn exflags(&self) -> u32 {
        unsafe { idalib_hexrays_cexpr_exflags(self.ptr) }
    }

    // --- Expression type checks ---

    /// Check if this is a function call.
    pub fn is_call(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_is_call(self.ptr) }
    }

    /// Check if this is a C string constant.
    pub fn is_cstr(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_is_cstr(self.ptr) }
    }

    /// Check if this is a floating point operation.
    pub fn is_fpop(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_is_fpop(self.ptr) }
    }

    /// Check if this expression has a "nice" form.
    pub fn is_nice(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_is_nice(self.ptr) }
    }

    /// Check if this is an undefined value.
    pub fn is_undef_val(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_is_undef_val(self.ptr) }
    }

    // --- Call arguments ---

    /// Get the call arguments (for cot_call).
    pub fn call_args(&self) -> Option<CArgList<'a>> {
        let ptr = unsafe { idalib_hexrays_cexpr_call_args(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(CArgList {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- Additional type checks ---

    /// Check if this expression's type is void.
    pub fn type_is_void(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_void(self.ptr) }
    }

    /// Check if this expression's type is a pointer to void.
    pub fn type_is_pvoid(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_pvoid(self.ptr) }
    }

    /// Check if this expression's type is a function pointer.
    pub fn type_is_funcptr(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_funcptr(self.ptr) }
    }

    /// Check if this expression's type is a boolean.
    pub fn type_is_bool(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_bool(self.ptr) }
    }

    /// Check if this expression's type is an enum.
    pub fn type_is_enum(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_enum(self.ptr) }
    }

    /// Check if this expression's type is const.
    pub fn type_is_const(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_const(self.ptr) }
    }

    /// Check if this expression's type is volatile.
    pub fn type_is_volatile(&self) -> bool {
        unsafe { idalib_hexrays_cexpr_type_is_volatile(self.ptr) }
    }

    /// Get the pointer depth (0 = not a pointer, 1 = T*, 2 = T**, etc.).
    pub fn type_ptr_depth(&self) -> i32 {
        unsafe { idalib_hexrays_cexpr_type_ptr_depth(self.ptr) }.into()
    }

    /// Get the array size if this is an array type. Returns -1 if not an array.
    pub fn type_array_size(&self) -> i64 {
        unsafe { idalib_hexrays_cexpr_type_array_size(self.ptr) }
    }

    /// Get the pointed-to type as a string (for pointer types).
    pub fn type_pointed_str(&self) -> String {
        unsafe { idalib_hexrays_cexpr_type_pointed_str(self.ptr) }
    }

    // --- Tree navigation helpers ---

    /// Check if this expression is a child of the given item.
    pub fn is_child_of(&self, parent: &CItem<'_>) -> bool {
        unsafe { idalib_hexrays_cexpr_is_child_of(self.ptr, parent.ptr) }
    }

    /// Check if the parent expression requires this expression to be an lvalue.
    pub fn requires_lvalue(&self, child: &CExpr<'_>) -> bool {
        unsafe { idalib_hexrays_cexpr_requires_lvalue(self.ptr, child.ptr) }
    }

    /// Check if this expression has the same effect as another.
    pub fn equal_effect(&self, other: &CExpr<'_>) -> bool {
        unsafe { idalib_hexrays_cexpr_equal_effect(self.ptr, other.ptr) }
    }
}

// ============================================================================
// CArgList - Function call arguments
// ============================================================================

/// A list of function call arguments.
pub struct CArgList<'a> {
    ptr: *mut carglist_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CArgList<'a> {
    /// Get the number of arguments.
    pub fn len(&self) -> usize {
        unsafe { idalib_hexrays_carglist_count(self.ptr) }
    }

    /// Check if the argument list is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get an argument by index.
    pub fn at(&self, idx: usize) -> Option<CArg<'a>> {
        let ptr = unsafe { idalib_hexrays_carglist_at(self.ptr, idx) };
        if ptr.is_null() {
            None
        } else {
            Some(CArg {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get an iterator over arguments.
    pub fn iter(&self) -> CArgListIter<'_> {
        CArgListIter {
            it: unsafe { idalib_hexrays_carglist_iter(self.ptr) },
            _marker: PhantomData,
        }
    }
}

impl<'a> IntoIterator for &'a CArgList<'a> {
    type Item = CArg<'a>;
    type IntoIter = CArgListIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over function call arguments.
pub struct CArgListIter<'a> {
    it: cxx::UniquePtr<carglist_iter>,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Iterator for CArgListIter<'a> {
    type Item = CArg<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = unsafe { idalib_hexrays_carglist_iter_next(self.it.pin_mut()) };
        if ptr.is_null() {
            None
        } else {
            Some(CArg {
                ptr,
                _marker: PhantomData,
            })
        }
    }
}

/// A function call argument.
///
/// This is an expression that also has information about whether
/// it's a vararg and its formal type.
pub struct CArg<'a> {
    ptr: *mut carg_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CArg<'a> {
    /// Get this argument as an expression.
    ///
    /// Note: `carg_t` extends `cexpr_t`, so this is a safe upcast.
    pub fn as_expr(&self) -> CExpr<'a> {
        CExpr {
            ptr: self.ptr as *mut cexpr_t,
            _marker: PhantomData,
        }
    }

    /// Check if this is a vararg argument.
    pub fn is_vararg(&self) -> bool {
        unsafe { idalib_hexrays_carg_is_vararg(self.ptr as *const _) }
    }

    /// Get the formal type as a string.
    pub fn formal_type_str(&self) -> String {
        unsafe { idalib_hexrays_carg_formal_type_str(self.ptr as *const _) }
    }
}

// ============================================================================
// LocalVar - Local variable
// ============================================================================

/// A local variable in a decompiled function.
///
/// # Example
///
/// ```rust,ignore
/// for lvar in cfunc.lvars() {
///     println!("Variable: {} : {}", lvar.name(), lvar.type_str());
///     if lvar.is_arg() {
///         println!("  (function argument)");
///     }
///     if lvar.is_stk_var() {
///         println!("  Stack offset: 0x{:x}", lvar.stkoff());
///     }
/// }
/// ```
pub struct LocalVar<'a> {
    ptr: *mut lvar_t,
    cfunc: *mut cfunc_t, // Optional - needed for modifications
    _marker: PhantomData<&'a ()>,
}

impl<'a> LocalVar<'a> {
    /// Get the variable name.
    pub fn name(&self) -> String {
        unsafe { idalib_hexrays_lvar_name(self.ptr) }
    }

    /// Get the variable type as a string.
    pub fn type_str(&self) -> String {
        unsafe { idalib_hexrays_lvar_type_str(self.ptr) }
    }

    /// Get the variable comment.
    pub fn comment(&self) -> String {
        unsafe { idalib_hexrays_lvar_cmt(self.ptr) }
    }

    /// Get the variable width in bytes.
    pub fn width(&self) -> i32 {
        unsafe { idalib_hexrays_lvar_width(self.ptr) }.into()
    }

    /// Get the definition block number.
    pub fn defblk(&self) -> i32 {
        unsafe { idalib_hexrays_lvar_defblk(self.ptr) }.into()
    }

    /// Get the definition address.
    pub fn defea(&self) -> Address {
        unsafe { idalib_hexrays_lvar_defea(self.ptr) }
    }

    /// Check if this is a function argument.
    pub fn is_arg(&self) -> bool {
        unsafe { idalib_hexrays_lvar_is_arg(self.ptr) }
    }

    /// Check if this is a return value.
    pub fn is_result(&self) -> bool {
        unsafe { idalib_hexrays_lvar_is_result(self.ptr) }
    }

    /// Check if this is a stack variable.
    pub fn is_stk_var(&self) -> bool {
        unsafe { idalib_hexrays_lvar_is_stk_var(self.ptr) }
    }

    /// Check if this is a register variable.
    pub fn is_reg_var(&self) -> bool {
        unsafe { idalib_hexrays_lvar_is_reg_var(self.ptr) }
    }

    /// Check if this is a floating point variable.
    pub fn is_floating(&self) -> bool {
        unsafe { idalib_hexrays_lvar_is_floating(self.ptr) }
    }

    /// Check if this variable has a type.
    pub fn is_typed(&self) -> bool {
        unsafe { idalib_hexrays_lvar_is_typed(self.ptr) }
    }

    /// Check if this is a fake variable.
    pub fn is_fake(&self) -> bool {
        unsafe { idalib_hexrays_lvar_is_fake(self.ptr) }
    }

    /// Check if this variable overlaps with others.
    pub fn is_overlapped(&self) -> bool {
        unsafe { idalib_hexrays_lvar_is_overlapped(self.ptr) }
    }

    /// Check if this variable is used.
    pub fn is_used(&self) -> bool {
        unsafe { idalib_hexrays_lvar_is_used(self.ptr) }
    }

    /// Check if this variable is used by reference.
    pub fn is_used_byref(&self) -> bool {
        unsafe { idalib_hexrays_lvar_is_used_byref(self.ptr) }
    }

    /// Check if this is the 'this' argument.
    pub fn is_thisarg(&self) -> bool {
        unsafe { idalib_hexrays_lvar_is_thisarg(self.ptr) }
    }

    /// Check if this variable has a user-defined name.
    pub fn has_user_name(&self) -> bool {
        unsafe { idalib_hexrays_lvar_has_user_name(self.ptr) }
    }

    /// Check if this variable has a user-defined type.
    pub fn has_user_type(&self) -> bool {
        unsafe { idalib_hexrays_lvar_has_user_type(self.ptr) }
    }

    /// Check if this variable has a "nice" name.
    pub fn has_nice_name(&self) -> bool {
        unsafe { idalib_hexrays_lvar_has_nice_name(self.ptr) }
    }

    /// Get the stack offset (for stack variables).
    pub fn stkoff(&self) -> i64 {
        unsafe { idalib_hexrays_lvar_get_stkoff(self.ptr) }
    }

    /// Get the register number (for register variables).
    pub fn reg(&self) -> i32 {
        unsafe { idalib_hexrays_lvar_get_reg(self.ptr) }.into()
    }

    // --- Modification methods ---

    /// Set the variable's comment.
    pub fn set_comment(&self, comment: &str) {
        if let Ok(c_cmt) = std::ffi::CString::new(comment) {
            unsafe { idalib_hexrays_lvar_set_cmt(self.ptr, c_cmt.as_ptr()) };
        }
    }

    /// Set the variable's type.
    ///
    /// Note: This method only works if this LocalVar was obtained from
    /// CFunction::lvar_at() or CFunction::find_lvar_by_name().
    pub fn set_type(&self, type_str: &str) -> bool {
        if self.cfunc.is_null() {
            return false;
        }
        if let Ok(c_type) = std::ffi::CString::new(type_str) {
            unsafe { idalib_hexrays_lvar_set_type(self.cfunc, self.ptr, c_type.as_ptr()) }
        } else {
            false
        }
    }

    /// Rename the variable.
    ///
    /// Note: This method only works if this LocalVar was obtained from
    /// CFunction::lvar_at() or CFunction::find_lvar_by_name().
    pub fn set_name(&self, name: &str) -> bool {
        if self.cfunc.is_null() {
            return false;
        }
        if let Ok(c_name) = std::ffi::CString::new(name) {
            unsafe { idalib_hexrays_lvar_set_name(self.cfunc, self.ptr, c_name.as_ptr()) }
        } else {
            false
        }
    }
}

/// Iterator over local variables.
pub struct LocalVarIter<'a> {
    it: cxx::UniquePtr<lvars_iter>,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Iterator for LocalVarIter<'a> {
    type Item = LocalVar<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = unsafe { idalib_hexrays_lvars_iter_next(self.it.pin_mut()) };
        if ptr.is_null() {
            None
        } else {
            Some(LocalVar {
                ptr,
                cfunc: std::ptr::null_mut(), // Not available through iterator
                _marker: PhantomData,
            })
        }
    }
}

// ============================================================================
// Microcode types
// ============================================================================

/// Microcode array (mba_t).
///
/// The microcode is an intermediate representation used by the decompiler
/// before generating the C-tree. It consists of basic blocks containing
/// microcode instructions.
pub struct Mba<'a> {
    ptr: *mut mba_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Mba<'a> {
    /// Get the number of basic blocks.
    pub fn qty(&self) -> i32 {
        unsafe { idalib_hexrays_mba_qty(self.ptr) }.into()
    }

    /// Get the function entry address.
    pub fn entry_ea(&self) -> Address {
        unsafe { idalib_hexrays_mba_entry_ea(self.ptr) }
    }

    /// Get the microcode maturity level.
    pub fn maturity(&self) -> i32 {
        unsafe { idalib_hexrays_mba_maturity(self.ptr) }.into()
    }

    /// Get a basic block by index.
    pub fn get_mblock(&self, idx: i32) -> Option<Mblock<'a>> {
        let ptr = unsafe { idalib_hexrays_mba_get_mblock(self.ptr, c_int(idx)) };
        if ptr.is_null() {
            None
        } else {
            Some(Mblock {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Iterate over all basic blocks.
    pub fn blocks(&self) -> impl Iterator<Item = Mblock<'a>> + '_ {
        (0..self.qty()).filter_map(|i| self.get_mblock(i))
    }

    // --- Additional properties ---

    /// Get the stack frame size.
    pub fn stack_size(&self) -> i64 {
        unsafe { idalib_hexrays_mba_stacksize(self.ptr) }
    }

    /// Get the number of arguments.
    pub fn args_count(&self) -> i32 {
        unsafe { idalib_hexrays_mba_argidx_size(self.ptr) }.into()
    }

    /// Get the minimum address in the function ranges.
    pub fn min_ea(&self) -> Address {
        unsafe { idalib_hexrays_mba_minea(self.ptr) }
    }

    /// Get the first epilog address.
    pub fn first_epilog_ea(&self) -> Address {
        unsafe { idalib_hexrays_mba_first_epilog_ea(self.ptr) }
    }

    /// Check if this is a thunk function.
    pub fn is_thunk(&self) -> bool {
        unsafe { idalib_hexrays_mba_is_thunk(self.ptr) }
    }

    /// Check if short display is enabled.
    pub fn is_short(&self) -> bool {
        unsafe { idalib_hexrays_mba_is_short(self.ptr) }
    }

    /// Check if this function has pass-through registers.
    pub fn has_passregs(&self) -> bool {
        unsafe { idalib_hexrays_mba_has_passregs(self.ptr) }
    }

    // --- Additional MBA flags ---

    /// Check if call information has been built.
    pub fn has_calls(&self) -> bool {
        unsafe { idalib_hexrays_mba_has_calls(self.ptr) }
    }

    /// Check if this is a microcode pattern.
    pub fn is_pattern(&self) -> bool {
        unsafe { idalib_hexrays_mba_is_pattern(self.ptr) }
    }

    /// Check if the function returns a floating point value.
    pub fn returns_float(&self) -> bool {
        unsafe { idalib_hexrays_mba_returns_float(self.ptr) }
    }

    /// Check if global optimization has been performed.
    pub fn has_glbopt(&self) -> bool {
        unsafe { idalib_hexrays_mba_has_glbopt(self.ptr) }
    }

    /// Check if stack variables and arguments are treated as one area.
    pub fn is_cmnstk(&self) -> bool {
        unsafe { idalib_hexrays_mba_is_cmnstk(self.ptr) }
    }

    /// Get the MBA flags.
    pub fn flags(&self) -> u32 {
        unsafe { idalib_hexrays_mba_flags(self.ptr) }
    }

    /// Get the final maturity level constant.
    pub fn final_maturity() -> i32 {
        unsafe { idalib_hexrays_mba_final_maturity() }.into()
    }
}

/// A microcode basic block (mblock_t).
pub struct Mblock<'a> {
    ptr: *mut mblock_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Mblock<'a> {
    /// Get the block serial number.
    pub fn serial(&self) -> i32 {
        unsafe { idalib_hexrays_mblock_serial(self.ptr) }.into()
    }

    /// Get the start address of this block.
    pub fn start(&self) -> Address {
        unsafe { idalib_hexrays_mblock_start(self.ptr) }
    }

    /// Get the end address of this block.
    pub fn end(&self) -> Address {
        unsafe { idalib_hexrays_mblock_end(self.ptr) }
    }

    /// Get the block type.
    pub fn block_type(&self) -> i32 {
        unsafe { idalib_hexrays_mblock_type(self.ptr) }.into()
    }

    /// Get the number of predecessors.
    pub fn npred(&self) -> i32 {
        unsafe { idalib_hexrays_mblock_npred(self.ptr) }.into()
    }

    /// Get the number of successors.
    pub fn nsucc(&self) -> i32 {
        unsafe { idalib_hexrays_mblock_nsucc(self.ptr) }.into()
    }

    /// Get a predecessor block number.
    pub fn pred(&self, idx: i32) -> i32 {
        unsafe { idalib_hexrays_mblock_pred(self.ptr, c_int(idx)) }.into()
    }

    /// Get a successor block number.
    pub fn succ(&self, idx: i32) -> i32 {
        unsafe { idalib_hexrays_mblock_succ(self.ptr, c_int(idx)) }.into()
    }

    /// Get the first instruction in this block.
    pub fn head(&self) -> Option<Minsn<'a>> {
        let ptr = unsafe { idalib_hexrays_mblock_head(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(Minsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the last instruction in this block.
    pub fn tail(&self) -> Option<Minsn<'a>> {
        let ptr = unsafe { idalib_hexrays_mblock_tail(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(Minsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Iterate over all instructions in this block.
    pub fn instructions(&self) -> MblockInsnIter<'a> {
        MblockInsnIter {
            current: self.head(),
        }
    }

    // --- Block predicates ---

    /// Check if this block ends with a call instruction.
    pub fn is_call_block(&self) -> bool {
        unsafe { idalib_hexrays_mblock_is_call_block(self.ptr) }
    }

    /// Check if this block ends with an unknown call.
    pub fn is_unknown_call(&self) -> bool {
        unsafe { idalib_hexrays_mblock_is_unknown_call(self.ptr) }
    }

    /// Check if this is an n-way block (switch).
    pub fn is_nway(&self) -> bool {
        unsafe { idalib_hexrays_mblock_is_nway(self.ptr) }
    }

    /// Check if this is a branch (conditional 2-way) block.
    pub fn is_branch(&self) -> bool {
        unsafe { idalib_hexrays_mblock_is_branch(self.ptr) }
    }

    /// Check if this is a simple goto block.
    pub fn is_simple_goto_block(&self) -> bool {
        unsafe { idalib_hexrays_mblock_is_simple_goto_block(self.ptr) }
    }

    /// Check if this is a simple conditional jump block.
    pub fn is_simple_jcnd_block(&self) -> bool {
        unsafe { idalib_hexrays_mblock_is_simple_jcnd_block(self.ptr) }
    }

    /// Check if this block is empty (no instructions).
    pub fn is_empty(&self) -> bool {
        unsafe { idalib_hexrays_mblock_is_empty(self.ptr) }
    }

    /// Check if this is a fake block.
    pub fn is_fake(&self) -> bool {
        unsafe { idalib_hexrays_mblock_is_fake(self.ptr) }
    }

    /// Check if this block is a goto target.
    pub fn is_goto_target(&self) -> bool {
        unsafe { idalib_hexrays_mblock_is_goto_target(self.ptr) }
    }

    /// Check if this is a dead-end block (doesn't return).
    pub fn is_noret(&self) -> bool {
        unsafe { idalib_hexrays_mblock_is_noret(self.ptr) }
    }

    /// Get the block flags.
    pub fn flags(&self) -> u32 {
        unsafe { idalib_hexrays_mblock_flags(self.ptr) }
    }

    /// Count the number of instructions in this block.
    pub fn insn_count(&self) -> usize {
        unsafe { idalib_hexrays_mblock_insn_count(self.ptr) }
    }
}

/// Iterator over instructions in a basic block.
pub struct MblockInsnIter<'a> {
    current: Option<Minsn<'a>>,
}

impl<'a> Iterator for MblockInsnIter<'a> {
    type Item = Minsn<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current.take()?;
        self.current = current.next();
        Some(current)
    }
}

/// A microcode instruction (minsn_t).
pub struct Minsn<'a> {
    ptr: *mut minsn_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Minsn<'a> {
    /// Get the address of this instruction.
    pub fn ea(&self) -> Address {
        unsafe { idalib_hexrays_minsn_ea(self.ptr) }
    }

    /// Get the opcode of this instruction.
    pub fn opcode(&self) -> i32 {
        unsafe { idalib_hexrays_minsn_opcode(self.ptr) }.into()
    }

    /// Get the next instruction.
    pub fn next(&self) -> Option<Minsn<'a>> {
        let ptr = unsafe { idalib_hexrays_minsn_next(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(Minsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the previous instruction.
    pub fn prev(&self) -> Option<Minsn<'a>> {
        let ptr = unsafe { idalib_hexrays_minsn_prev(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(Minsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get a string representation of this instruction.
    pub fn dstr(&self) -> String {
        unsafe { idalib_hexrays_minsn_dstr(self.ptr) }
    }

    /// Get the name of this instruction's opcode.
    pub fn opcode_name(&self) -> String {
        mcode_name(self.opcode())
    }

    // --- Operand access ---

    /// Get the left operand.
    pub fn left(&self) -> Option<Mop<'a>> {
        let ptr = unsafe { idalib_hexrays_minsn_l(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(Mop {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the right operand.
    pub fn right(&self) -> Option<Mop<'a>> {
        let ptr = unsafe { idalib_hexrays_minsn_r(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(Mop {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the destination operand.
    pub fn dest(&self) -> Option<Mop<'a>> {
        let ptr = unsafe { idalib_hexrays_minsn_d(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(Mop {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- Instruction type checks ---

    /// Check if this is a call instruction.
    pub fn is_call(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_call(self.ptr) }
    }

    /// Check if this is a jump instruction.
    pub fn is_jump(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_jump(self.ptr) }
    }

    /// Check if this is a conditional instruction.
    pub fn is_conditional(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_cond(self.ptr) }
    }

    /// Check if this instruction modifies the destination operand.
    pub fn modifies_dest(&self) -> bool {
        unsafe { idalib_hexrays_minsn_modifies_d(self.ptr) }
    }

    /// Find a call instruction starting from this instruction.
    pub fn find_call(&self, with_helpers: bool) -> Option<Minsn<'a>> {
        let ptr = unsafe { idalib_hexrays_minsn_find_call(self.ptr, with_helpers) };
        if ptr.is_null() {
            None
        } else {
            Some(Minsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    // --- Additional predicates ---

    /// Check if this is a tail call.
    pub fn is_tailcall(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_tailcall(self.ptr) }
    }

    /// Check if this is a floating point instruction.
    pub fn is_fpinsn(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_fpinsn(self.ptr) }
    }

    /// Check if this is an assertion instruction.
    pub fn is_assert(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_assert(self.ptr) }
    }

    /// Check if this instruction is persistent.
    pub fn is_persistent(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_persistent(self.ptr) }
    }

    /// Check if this instruction has been combined from multiple instructions.
    pub fn is_combined(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_combined(self.ptr) }
    }

    /// Check if this is a far call.
    pub fn is_farcall(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_farcall(self.ptr) }
    }

    /// Check if this is a stack-cleaning pop.
    pub fn is_cleaning_pop(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_cleaning_pop(self.ptr) }
    }

    /// Check if this instruction is propagatable.
    pub fn is_propagatable(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_propagatable(self.ptr) }
    }

    /// Check if this instruction uses wild matching.
    pub fn is_wild_match(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_wild_match(self.ptr) }
    }

    /// Check if this was a noret indirect call.
    pub fn was_noret_icall(&self) -> bool {
        unsafe { idalib_hexrays_minsn_was_noret_icall(self.ptr) }
    }

    /// Check if this instruction moves multiple registers.
    pub fn is_multimov(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_multimov(self.ptr) }
    }

    /// Check if this is an unknown call.
    pub fn is_unknown_call(&self) -> bool {
        unsafe { idalib_hexrays_minsn_is_unknown_call(self.ptr) }
    }

    /// Get the instruction properties flags.
    pub fn iprops(&self) -> i32 {
        unsafe { idalib_hexrays_minsn_iprops(self.ptr) }.into()
    }

    /// Get the next instruction, skipping nops.
    pub fn nexti(&self) -> Option<Minsn<'a>> {
        let ptr = unsafe { idalib_hexrays_minsn_nexti(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(Minsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Get the previous instruction, skipping nops.
    pub fn previ(&self) -> Option<Minsn<'a>> {
        let ptr = unsafe { idalib_hexrays_minsn_previ(self.ptr) };
        if ptr.is_null() {
            None
        } else {
            Some(Minsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }
}

/// Get the name of a microcode opcode.
pub fn mcode_name(opcode: i32) -> String {
    unsafe { idalib_hexrays_mcode_name(c_int(opcode)) }
}

// ============================================================================
// Mop - Microcode operand
// ============================================================================

/// Microcode operand type constants.
pub mod mop_type {
    //! Microcode operand type constants.

    use super::*;

    /// No operand (mop_z)
    pub fn z() -> i32 {
        unsafe { idalib_hexrays_mop_z() }.into()
    }
    /// Register (mop_r)
    pub fn r() -> i32 {
        unsafe { idalib_hexrays_mop_r() }.into()
    }
    /// Immediate number (mop_n)
    pub fn n() -> i32 {
        unsafe { idalib_hexrays_mop_n() }.into()
    }
    /// String constant (mop_str)
    pub fn str() -> i32 {
        unsafe { idalib_hexrays_mop_str_const() }.into()
    }
    /// Result of another instruction (mop_d)
    pub fn d() -> i32 {
        unsafe { idalib_hexrays_mop_d_const() }.into()
    }
    /// Stack variable (mop_S)
    pub fn stack() -> i32 {
        unsafe { idalib_hexrays_mop_S() }.into()
    }
    /// Global variable (mop_v)
    pub fn global() -> i32 {
        unsafe { idalib_hexrays_mop_v() }.into()
    }
    /// Block number (mop_b)
    pub fn block() -> i32 {
        unsafe { idalib_hexrays_mop_b() }.into()
    }
    /// Floating point constant (mop_f)
    pub fn fconst() -> i32 {
        unsafe { idalib_hexrays_mop_f() }.into()
    }
    /// Local variable (mop_l)
    pub fn lvar() -> i32 {
        unsafe { idalib_hexrays_mop_l() }.into()
    }
    /// Address of operand (mop_a)
    pub fn addr() -> i32 {
        unsafe { idalib_hexrays_mop_a() }.into()
    }
    /// Helper function (mop_h)
    pub fn helper() -> i32 {
        unsafe { idalib_hexrays_mop_h() }.into()
    }
    /// Switch cases (mop_c)
    pub fn cases() -> i32 {
        unsafe { idalib_hexrays_mop_c() }.into()
    }
    /// Function (for calls) (mop_fn)
    pub fn func() -> i32 {
        unsafe { idalib_hexrays_mop_fn() }.into()
    }
    /// Pair of operands (mop_p)
    pub fn pair() -> i32 {
        unsafe { idalib_hexrays_mop_p() }.into()
    }
    /// Scattered (mop_sc)
    pub fn scattered() -> i32 {
        unsafe { idalib_hexrays_mop_sc() }.into()
    }
}

/// A microcode operand (mop_t).
pub struct Mop<'a> {
    ptr: *mut mop_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Mop<'a> {
    /// Get the operand type.
    pub fn op_type(&self) -> i32 {
        unsafe { idalib_hexrays_mop_type(self.ptr) }.into()
    }

    /// Get the operand size in bytes.
    pub fn size(&self) -> i32 {
        unsafe { idalib_hexrays_mop_size(self.ptr) }.into()
    }

    /// Get as string representation.
    pub fn dstr(&self) -> String {
        unsafe { idalib_hexrays_mop_dstr(self.ptr) }
    }

    // --- Type checks ---

    /// Check if this is a number operand.
    pub fn is_number(&self) -> bool {
        unsafe { idalib_hexrays_mop_is_number(self.ptr) }
    }

    /// Check if this is a register operand.
    pub fn is_reg(&self) -> bool {
        unsafe { idalib_hexrays_mop_is_reg(self.ptr) }
    }

    /// Check if this is a stack operand.
    pub fn is_stack(&self) -> bool {
        unsafe { idalib_hexrays_mop_is_stk(self.ptr) }
    }

    /// Check if this is a local variable operand.
    pub fn is_lvar(&self) -> bool {
        unsafe { idalib_hexrays_mop_is_lvar(self.ptr) }
    }

    /// Check if this is a global variable operand.
    pub fn is_global(&self) -> bool {
        unsafe { idalib_hexrays_mop_is_glb(self.ptr) }
    }

    /// Check if this is an address operand.
    pub fn is_addr(&self) -> bool {
        unsafe { idalib_hexrays_mop_is_addr(self.ptr) }
    }

    /// Check if this is a sub-instruction operand.
    pub fn is_insn(&self) -> bool {
        unsafe { idalib_hexrays_mop_is_insn(self.ptr) }
    }

    // --- Value access ---

    /// Get register number (for register operands).
    pub fn reg(&self) -> Option<i32> {
        if self.is_reg() {
            Some(unsafe { idalib_hexrays_mop_reg(self.ptr) }.into())
        } else {
            None
        }
    }

    /// Get immediate value (for number operands).
    pub fn number_value(&self) -> Option<u64> {
        if self.is_number() {
            Some(unsafe { idalib_hexrays_mop_nnn_value(self.ptr) })
        } else {
            None
        }
    }

    /// Get stack offset (for stack operands).
    pub fn stack_offset(&self) -> Option<i64> {
        if self.is_stack() {
            Some(unsafe { idalib_hexrays_mop_stkoff(self.ptr) })
        } else {
            None
        }
    }

    /// Get local variable index (for lvar operands).
    pub fn lvar_idx(&self) -> Option<i32> {
        if self.is_lvar() {
            let idx: i32 = unsafe { idalib_hexrays_mop_lvar_idx(self.ptr) }.into();
            if idx >= 0 { Some(idx) } else { None }
        } else {
            None
        }
    }

    /// Get global address (for global operands).
    pub fn global_addr(&self) -> Option<Address> {
        if self.is_global() {
            Some(unsafe { idalib_hexrays_mop_glbaddr(self.ptr) })
        } else {
            None
        }
    }

    /// Get the target operand (for address operands).
    pub fn addr_target(&self) -> Option<Mop<'a>> {
        if self.is_addr() {
            let ptr = unsafe { idalib_hexrays_mop_addr_target(self.ptr) as *mut mop_t };
            if ptr.is_null() {
                None
            } else {
                Some(Mop {
                    ptr,
                    _marker: PhantomData,
                })
            }
        } else {
            None
        }
    }

    /// Get the sub-instruction (for instruction operands).
    pub fn insn(&self) -> Option<Minsn<'a>> {
        if self.is_insn() {
            let ptr = unsafe { idalib_hexrays_mop_insn(self.ptr) };
            if ptr.is_null() {
                None
            } else {
                Some(Minsn {
                    ptr,
                    _marker: PhantomData,
                })
            }
        } else {
            None
        }
    }
}

// ============================================================================
// Mcode helpers
// ============================================================================

/// Get the category of a microcode opcode.
pub fn mcode_category(opcode: i32) -> i32 {
    unsafe { idalib_hexrays_mcode_category(c_int(opcode)) }.into()
}

/// Check if a microcode opcode modifies memory.
pub fn mcode_modifies_mem(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_modifies_mem(c_int(opcode)) }
}

/// Check if a microcode opcode reads memory.
pub fn mcode_reads_mem(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_reads_mem(c_int(opcode)) }
}

/// Check if a microcode opcode is a comparison.
pub fn mcode_is_comparison(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_is_comparison(c_int(opcode)) }
}

/// Check if a microcode opcode is arithmetic.
pub fn mcode_is_arithmetic(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_is_arithmetic(c_int(opcode)) }
}

/// Check if a microcode opcode is bitwise.
pub fn mcode_is_bitwise(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_is_bitwise(c_int(opcode)) }
}

/// Check if a microcode opcode is a conditional jump (jcc).
pub fn mcode_is_jcc(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_is_jcc(c_int(opcode)) }
}

/// Check if a microcode opcode is a setcc (conditional set).
pub fn mcode_is_set(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_is_set(c_int(opcode)) }
}

/// Check if a microcode opcode is a floating-point instruction.
pub fn mcode_is_fpu(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_is_fpu(c_int(opcode)) }
}

/// Check if a microcode opcode is a call instruction.
pub fn mcode_is_call(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_is_call(c_int(opcode)) }
}

/// Check if a microcode opcode is a jump instruction.
pub fn mcode_is_jump(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_is_jump(c_int(opcode)) }
}

/// Check if a microcode opcode is a return instruction.
pub fn mcode_is_ret(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_is_ret(c_int(opcode)) }
}

/// Check if a microcode opcode modifies the destination operand.
pub fn mcode_modifies_d(opcode: i32) -> bool {
    unsafe { idalib_hexrays_mcode_modifies_d(c_int(opcode)) }
}

/// Check if a microcode opcode is propagatable (for optimization).
pub fn is_mcode_propagatable(opcode: i32) -> bool {
    unsafe { idalib_hexrays_is_mcode_propagatable(c_int(opcode)) }
}

/// Check if a microcode opcode must close a basic block.
pub fn must_mcode_close_block(opcode: i32, including_calls: bool) -> bool {
    unsafe { idalib_hexrays_must_mcode_close_block(c_int(opcode), including_calls) }
}

/// Negate a conditional relation opcode (e.g., jz -> jnz, jae -> jb).
/// Returns the negated opcode.
pub fn negate_mcode_relation(opcode: i32) -> i32 {
    unsafe { idalib_hexrays_negate_mcode_relation(c_int(opcode)) }.into()
}

/// Swap a conditional relation opcode (e.g., jb -> ja, jle -> jge).
/// Returns the swapped opcode.
pub fn swap_mcode_relation(opcode: i32) -> i32 {
    unsafe { idalib_hexrays_swap_mcode_relation(c_int(opcode)) }.into()
}

/// Get the signed version of a comparison opcode.
/// Returns the signed opcode.
pub fn get_signed_mcode(opcode: i32) -> i32 {
    unsafe { idalib_hexrays_get_signed_mcode(c_int(opcode)) }.into()
}

/// Get the unsigned version of a comparison opcode.
/// Returns the unsigned opcode.
pub fn get_unsigned_mcode(opcode: i32) -> i32 {
    unsafe { idalib_hexrays_get_unsigned_mcode(c_int(opcode)) }.into()
}

/// Get a description of a microcode error code.
pub fn get_merror_desc(code: i32) -> String {
    unsafe { idalib_hexrays_get_merror_desc(c_int(code)) }
}

/// Microcode error codes (merror_t).
pub mod merror {
    use crate::ffi::hexrays::*;

    /// No error
    pub fn ok() -> i32 {
        unsafe { idalib_hexrays_merr_ok() }.into()
    }
    /// Internal error
    pub fn interr() -> i32 {
        unsafe { idalib_hexrays_merr_interr() }.into()
    }
    /// Cannot convert to microcode
    pub fn insn() -> i32 {
        unsafe { idalib_hexrays_merr_insn() }.into()
    }
    /// Memory reference expected
    pub fn mem() -> i32 {
        unsafe { idalib_hexrays_merr_mem() }.into()
    }
    /// Invalid base address
    pub fn badblk() -> i32 {
        unsafe { idalib_hexrays_merr_badblk() }.into()
    }
    /// Bad stack pointer
    pub fn badsp() -> i32 {
        unsafe { idalib_hexrays_merr_badsp() }.into()
    }
    /// Positive stack pointer
    pub fn prolog() -> i32 {
        unsafe { idalib_hexrays_merr_prolog() }.into()
    }
    /// Switch analysis failed
    pub fn switch_val() -> i32 {
        unsafe { idalib_hexrays_merr_switch() }.into()
    }
    /// Exception handler
    pub fn exception() -> i32 {
        unsafe { idalib_hexrays_merr_exception() }.into()
    }
    /// Function too large (stack)
    pub fn hugestack() -> i32 {
        unsafe { idalib_hexrays_merr_hugestack() }.into()
    }
    /// Too many local variables
    pub fn lvars() -> i32 {
        unsafe { idalib_hexrays_merr_lvars() }.into()
    }
    /// Bitness conflict
    pub fn bitness() -> i32 {
        unsafe { idalib_hexrays_merr_bitness() }.into()
    }
    /// Bad call type
    pub fn badcall() -> i32 {
        unsafe { idalib_hexrays_merr_badcall() }.into()
    }
    /// Bad frame
    pub fn badframe() -> i32 {
        unsafe { idalib_hexrays_merr_badframe() }.into()
    }
    /// Bad database
    pub fn badidb() -> i32 {
        unsafe { idalib_hexrays_merr_badidb() }.into()
    }
    /// Sizeof failure
    pub fn sizeof_err() -> i32 {
        unsafe { idalib_hexrays_merr_sizeof() }.into()
    }
    /// Redo decompilation
    pub fn redo() -> i32 {
        unsafe { idalib_hexrays_merr_redo() }.into()
    }
    /// Decompilation cancelled
    pub fn canceled() -> i32 {
        unsafe { idalib_hexrays_merr_canceled() }.into()
    }
    /// Recursion depth exceeded
    pub fn recdepth() -> i32 {
        unsafe { idalib_hexrays_merr_recdepth() }.into()
    }
    /// Overlapping ranges
    pub fn overlap() -> i32 {
        unsafe { idalib_hexrays_merr_overlap() }.into()
    }
    /// Partial initialization detected
    pub fn partinit() -> i32 {
        unsafe { idalib_hexrays_merr_partinit() }.into()
    }
    /// Complex function
    pub fn complex() -> i32 {
        unsafe { idalib_hexrays_merr_complex() }.into()
    }
    /// License error
    pub fn license() -> i32 {
        unsafe { idalib_hexrays_merr_license() }.into()
    }
    /// Decompiler is busy
    pub fn busy() -> i32 {
        unsafe { idalib_hexrays_merr_busy() }.into()
    }
    /// Function size limit exceeded
    pub fn funcsize() -> i32 {
        unsafe { idalib_hexrays_merr_funcsize() }.into()
    }
    /// Bad ranges
    pub fn badranges() -> i32 {
        unsafe { idalib_hexrays_merr_badranges() }.into()
    }
    /// Unsupported architecture
    pub fn badarch() -> i32 {
        unsafe { idalib_hexrays_merr_badarch() }.into()
    }
}

// ============================================================================
// Hexrays Decompiler Callbacks
// ============================================================================

use std::sync::Mutex;

/// Hexrays event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum HexraysEvent {
    /// Flowchart has been generated
    Flowchart,
    /// Stack points have been calculated
    Stkpnts,
    /// Prolog analysis finished
    Prolog,
    /// Microcode has been generated
    Microcode,
    /// Microcode has been preoptimized
    Preoptimized,
    /// Local optimization finished
    Locopt,
    /// Preallocation step begins
    Prealloc,
    /// Global optimization finished
    Glbopt,
    /// Structural analysis finished
    Structural,
    /// Ctree maturity level changed
    Maturity,
    /// Internal error
    Interr,
    /// Trying to combine instructions
    Combine,
    /// Printing ctree
    PrintFunc,
    /// Function text generated
    FuncPrinted,
    /// Resolving stack addresses
    ResolveStkaddrs,
    /// Building call info
    BuildCallinfo,
    /// All calls analyzed
    CallsDone,
    /// Unknown event
    Unknown(i32),
}

impl HexraysEvent {
    fn from_code(code: i32) -> Self {
        let flowchart = unsafe { idalib_hexrays_hxe_flowchart() }.into();
        let stkpnts = unsafe { idalib_hexrays_hxe_stkpnts() }.into();
        let prolog = unsafe { idalib_hexrays_hxe_prolog() }.into();
        let microcode = unsafe { idalib_hexrays_hxe_microcode() }.into();
        let preoptimized = unsafe { idalib_hexrays_hxe_preoptimized() }.into();
        let locopt = unsafe { idalib_hexrays_hxe_locopt() }.into();
        let prealloc = unsafe { idalib_hexrays_hxe_prealloc() }.into();
        let glbopt = unsafe { idalib_hexrays_hxe_glbopt() }.into();
        let structural = unsafe { idalib_hexrays_hxe_structural() }.into();
        let maturity = unsafe { idalib_hexrays_hxe_maturity() }.into();
        let interr = unsafe { idalib_hexrays_hxe_interr() }.into();
        let combine = unsafe { idalib_hexrays_hxe_combine() }.into();
        let print_func = unsafe { idalib_hexrays_hxe_print_func() }.into();
        let func_printed = unsafe { idalib_hexrays_hxe_func_printed() }.into();
        let resolve_stkaddrs = unsafe { idalib_hexrays_hxe_resolve_stkaddrs() }.into();
        let build_callinfo = unsafe { idalib_hexrays_hxe_build_callinfo() }.into();
        let calls_done = unsafe { idalib_hexrays_hxe_calls_done() }.into();

        match code {
            c if c == flowchart => HexraysEvent::Flowchart,
            c if c == stkpnts => HexraysEvent::Stkpnts,
            c if c == prolog => HexraysEvent::Prolog,
            c if c == microcode => HexraysEvent::Microcode,
            c if c == preoptimized => HexraysEvent::Preoptimized,
            c if c == locopt => HexraysEvent::Locopt,
            c if c == prealloc => HexraysEvent::Prealloc,
            c if c == glbopt => HexraysEvent::Glbopt,
            c if c == structural => HexraysEvent::Structural,
            c if c == maturity => HexraysEvent::Maturity,
            c if c == interr => HexraysEvent::Interr,
            c if c == combine => HexraysEvent::Combine,
            c if c == print_func => HexraysEvent::PrintFunc,
            c if c == func_printed => HexraysEvent::FuncPrinted,
            c if c == resolve_stkaddrs => HexraysEvent::ResolveStkaddrs,
            c if c == build_callinfo => HexraysEvent::BuildCallinfo,
            c if c == calls_done => HexraysEvent::CallsDone,
            _ => HexraysEvent::Unknown(code),
        }
    }

    /// Get the event name as a string
    pub fn name(&self) -> &'static str {
        match self {
            HexraysEvent::Flowchart => "flowchart",
            HexraysEvent::Stkpnts => "stkpnts",
            HexraysEvent::Prolog => "prolog",
            HexraysEvent::Microcode => "microcode",
            HexraysEvent::Preoptimized => "preoptimized",
            HexraysEvent::Locopt => "locopt",
            HexraysEvent::Prealloc => "prealloc",
            HexraysEvent::Glbopt => "glbopt",
            HexraysEvent::Structural => "structural",
            HexraysEvent::Maturity => "maturity",
            HexraysEvent::Interr => "interr",
            HexraysEvent::Combine => "combine",
            HexraysEvent::PrintFunc => "print_func",
            HexraysEvent::FuncPrinted => "func_printed",
            HexraysEvent::ResolveStkaddrs => "resolve_stkaddrs",
            HexraysEvent::BuildCallinfo => "build_callinfo",
            HexraysEvent::CallsDone => "calls_done",
            HexraysEvent::Unknown(_) => "unknown",
        }
    }
}

/// Data passed to the callback for each event
#[derive(Debug)]
pub struct HexraysEventData {
    /// The event type
    pub event: HexraysEvent,
    /// For maturity events: the new maturity level
    /// For interr events: the error code
    pub extra: i32,
    /// True if MBA data is available
    pub has_mba: bool,
    /// True if CFunc data is available
    pub has_cfunc: bool,
}

/// Callback function type for hexrays events
/// Return 0 to continue, non-zero to stop processing
pub type HexraysCallbackFn = Box<dyn Fn(&HexraysEventData) -> i32 + Send + Sync>;

/// Global storage for the callback
static HEXRAYS_CALLBACK: Mutex<Option<HexraysCallbackFn>> = Mutex::new(None);

/// The extern "C" function that C++ calls
#[unsafe(no_mangle)]
pub extern "C" fn idalib_hexrays_rust_event_handler(
    event: i32,
    mba: *mut mba_t,
    cfunc: *mut cfunc_t,
    extra: i32,
) -> i32 {
    let guard = match HEXRAYS_CALLBACK.lock() {
        Ok(g) => g,
        Err(_) => return 0, // Poisoned mutex, just continue
    };

    if let Some(ref callback) = *guard {
        let data = HexraysEventData {
            event: HexraysEvent::from_code(event),
            extra,
            has_mba: !mba.is_null(),
            has_cfunc: !cfunc.is_null(),
        };
        callback(&data)
    } else {
        0
    }
}

/// Install a hexrays event callback
///
/// Only one callback can be installed at a time. Installing a new callback
/// will replace any existing callback.
///
/// # Example
/// ```ignore
/// use idalib::decompiler::{install_hexrays_callback, HexraysEvent};
///
/// install_hexrays_callback(|data| {
///     println!("Event: {:?}", data.event);
///     0 // Continue processing
/// });
/// ```
pub fn install_hexrays_callback<F>(callback: F) -> bool
where
    F: Fn(&HexraysEventData) -> i32 + Send + Sync + 'static,
{
    let mut guard = match HEXRAYS_CALLBACK.lock() {
        Ok(g) => g,
        Err(_) => return false,
    };

    *guard = Some(Box::new(callback));

    // Install the C++ callback
    unsafe { idalib_hexrays_install_callback() }
}

/// Remove the hexrays event callback
pub fn remove_hexrays_callback() {
    let mut guard = match HEXRAYS_CALLBACK.lock() {
        Ok(g) => g,
        Err(_) => return,
    };

    *guard = None;

    unsafe { idalib_hexrays_remove_callback() }
}

/// Check if a hexrays callback is installed
pub fn has_hexrays_callback() -> bool {
    unsafe { idalib_hexrays_has_callback() }
}

/// Hexrays event type constants module
pub mod hxe {
    use crate::ffi::hexrays::*;

    /// Flowchart generated
    pub fn flowchart() -> i32 {
        unsafe { idalib_hexrays_hxe_flowchart() }.into()
    }
    /// Stack points calculated
    pub fn stkpnts() -> i32 {
        unsafe { idalib_hexrays_hxe_stkpnts() }.into()
    }
    /// Prolog analysis finished
    pub fn prolog() -> i32 {
        unsafe { idalib_hexrays_hxe_prolog() }.into()
    }
    /// Microcode generated
    pub fn microcode() -> i32 {
        unsafe { idalib_hexrays_hxe_microcode() }.into()
    }
    /// Microcode preoptimized
    pub fn preoptimized() -> i32 {
        unsafe { idalib_hexrays_hxe_preoptimized() }.into()
    }
    /// Local optimization finished
    pub fn locopt() -> i32 {
        unsafe { idalib_hexrays_hxe_locopt() }.into()
    }
    /// Preallocation step
    pub fn prealloc() -> i32 {
        unsafe { idalib_hexrays_hxe_prealloc() }.into()
    }
    /// Global optimization finished
    pub fn glbopt() -> i32 {
        unsafe { idalib_hexrays_hxe_glbopt() }.into()
    }
    /// Structural analysis finished
    pub fn structural() -> i32 {
        unsafe { idalib_hexrays_hxe_structural() }.into()
    }
    /// Ctree maturity changed
    pub fn maturity() -> i32 {
        unsafe { idalib_hexrays_hxe_maturity() }.into()
    }
    /// Internal error
    pub fn interr() -> i32 {
        unsafe { idalib_hexrays_hxe_interr() }.into()
    }
    /// Combining instructions
    pub fn combine() -> i32 {
        unsafe { idalib_hexrays_hxe_combine() }.into()
    }
    /// Printing function
    pub fn print_func() -> i32 {
        unsafe { idalib_hexrays_hxe_print_func() }.into()
    }
    /// Function printed
    pub fn func_printed() -> i32 {
        unsafe { idalib_hexrays_hxe_func_printed() }.into()
    }
    /// Resolving stack addresses
    pub fn resolve_stkaddrs() -> i32 {
        unsafe { idalib_hexrays_hxe_resolve_stkaddrs() }.into()
    }
    /// Building call info
    pub fn build_callinfo() -> i32 {
        unsafe { idalib_hexrays_hxe_build_callinfo() }.into()
    }
    /// All calls analyzed
    pub fn calls_done() -> i32 {
        unsafe { idalib_hexrays_hxe_calls_done() }.into()
    }
}
