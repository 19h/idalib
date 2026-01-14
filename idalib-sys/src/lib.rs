#![doc(html_no_source)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::identity_op)]
#![allow(clippy::needless_lifetimes)]
#![allow(unsafe_op_in_unsafe_fn)]

use std::path::PathBuf;

use autocxx::prelude::*;
use thiserror::Error;

mod platform;

#[derive(Debug, Error)]
pub enum IDAError {
    #[error(transparent)]
    Ffi(anyhow::Error),
    #[error(transparent)]
    HexRays(#[from] hexrays::HexRaysError),
    #[error("could not initialise IDA: error code {:x}", _0.0)]
    Init(c_int),
    #[error("could not create/open IDA database: input file `{0}` not found")]
    FileNotFound(PathBuf),
    #[error("could not open IDA database: error code {:x}", _0.0)]
    OpenDb(c_int),
    #[error("could not close IDA database: error code {:x}", _0.0)]
    CloseDb(c_int),
    #[error("invalid license")]
    InvalidLicense,
    #[error("could not generate pattern or signature files")]
    MakeSigs,
    #[error("could not get library version")]
    GetVersion,
}

impl IDAError {
    pub fn ffi<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Ffi(anyhow::Error::from(e))
    }

    pub fn ffi_with<M>(m: M) -> Self
    where
        M: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    {
        Self::Ffi(anyhow::Error::msg(m))
    }

    pub fn not_found(path: impl Into<PathBuf>) -> Self {
        Self::FileNotFound(path.into())
    }
}

include_cpp! {
    // NOTE: this fixes autocxx's inability to detect ea_t, optype_t as POD...
    #include "types.h"

    #include "auto.hpp"
    #include "bytes.hpp"
    #include "entry.hpp"
    #include "funcs.hpp"
    #include "gdl.hpp"
    #include "hexrays.hpp"
    #include "ida.hpp"
    #include "idalib.hpp"
    #include "idp.hpp"
    #include "loader.hpp"
    #include "moves.hpp"
    #include "nalt.hpp"
    #include "name.hpp"
    #include "pro.h"
    #include "segment.hpp"
    #include "strlist.hpp"
    #include "ua.hpp"
    #include "xref.hpp"

    generate!("qstring")

    // generate_pod!("cm_t")
    // generate_pod!("comp_t")
    // generate_pod!("compiler_info_t")
    generate_pod!("ea_t")
    generate_pod!("filetype_t")
    generate_pod!("range_t")
    generate_pod!("uval_t")

    // auto
    generate!("auto_wait")

    // bytes
    generate_pod!("flags64_t")
    generate!("is_data")
    generate!("is_code")
    generate!("get_flags")

    // entry
    generate!("get_entry")
    generate!("get_entry_ordinal")
    generate!("get_entry_qty")

    // idp
    generate!("processor_t")
    generate!("get_ph")
    generate!("is_align_insn")
    generate!("is_basic_block_end")
    generate!("is_call_insn")
    generate!("is_indirect_jump_insn")

    generate!("is_ret_insn")
    generate!("IRI_EXTENDED")
    generate!("IRI_RET_LITERALLY")
    generate!("IRI_SKIP_RETTARGET")
    generate!("IRI_STRICT") // default

    generate!("next_head")
    generate!("prev_head")

    generate!("str2reg")

    // funcs
    generate!("func_t")
    generate!("lock_func")
    generate!("get_func")
    generate!("get_func_num")
    generate!("get_func_qty")
    generate!("getn_func")

    generate!("calc_thunk_func_target")

    generate!("FUNC_NORET")
    generate!("FUNC_FAR")
    generate!("FUNC_LIB")
    generate!("FUNC_STATICDEF")
    generate!("FUNC_FRAME")
    generate!("FUNC_USERFAR")
    generate!("FUNC_HIDDEN")
    generate!("FUNC_THUNK")
    generate!("FUNC_BOTTOMBP")
    generate!("FUNC_NORET_PENDING")
    generate!("FUNC_SP_READY")
    generate!("FUNC_FUZZY_SP")
    generate!("FUNC_PROLOG_OK")
    generate!("FUNC_PURGED_OK")
    generate!("FUNC_TAIL")
    generate!("FUNC_LUMINA")
    generate!("FUNC_OUTLINE")
    generate!("FUNC_REANALYZE")
    generate!("FUNC_RESERVED")

    // gdl
    generate!("qbasic_block_t")
    generate!("qflow_chart_t")
    generate!("gdl_graph_t")
    generate_pod!("fc_block_type_t")

    generate!("FC_PRINT")
    generate!("FC_NOEXT")
    generate!("FC_RESERVED")
    generate!("FC_APPND")
    generate!("FC_CHKBREAK")
    generate!("FC_CALL_ENDS")
    generate!("FC_NOPREDS")
    generate!("FC_OUTLINES")

    // hexrays
    generate!("init_hexrays_plugin")
    generate!("term_hexrays_plugin")

    // generate!("decompile_func")
    generate!("cfuncptr_t")
    generate!("hexrays_failure_t")

    generate_pod!("merror_t")

    /*
    generate!("MERR_OK")
    generate!("MERR_BLOCK")
    generate!("MERR_INTERR")
    generate!("MERR_INSN")
    generate!("MERR_MEM")
    generate!("MERR_BADBLK")
    generate!("MERR_BADSP")
    generate!("MERR_PROLOG")
    generate!("MERR_SWITCH")
    generate!("MERR_EXCEPTION")
    generate!("MERR_HUGESTACK")
    generate!("MERR_LVARS")
    generate!("MERR_BITNESS")
    generate!("MERR_BADCALL")
    generate!("MERR_BADFRAME")
    generate!("MERR_UNKTYPE")
    generate!("MERR_BADIDB")
    generate!("MERR_SIZEOF")
    generate!("MERR_REDO")
    generate!("MERR_CANCELED")
    generate!("MERR_RECDEPTH")
    generate!("MERR_OVERLAP")
    generate!("MERR_PARTINIT")
    generate!("MERR_COMPLEX")
    generate!("MERR_LICENSE")
    generate!("MERR_ONLY")
    generate!("MERR_ONLY")
    generate!("MERR_BUSY")
    generate!("MERR_FARPTR")
    generate!("MERR_EXTERN")
    generate!("MERR_FUNCSIZE")
    generate!("MERR_BADRANGES")
    generate!("MERR_BADARCH")
    generate!("MERR_DSLOT")
    generate!("MERR_STOP")
    generate!("MERR_CLOUD")
    generate!("MERR_MAX_ERR")
    generate!("MERR_LOOP")
    */

    generate!("carg_t")
    generate!("carglist_t")

    extern_cpp_type!("cblock_t", crate::hexrays::cblock_t)
    extern_cpp_type!("cfunc_t", crate::hexrays::cfunc_t)
    extern_cpp_type!("citem_t", crate::hexrays::citem_t)
    extern_cpp_type!("cinsn_t", crate::hexrays::cinsn_t)
    extern_cpp_type!("cexpr_t", crate::hexrays::cexpr_t)
    extern_cpp_type!("cswitch_t", crate::hexrays::cswitch_t)
    extern_cpp_type!("ctry_t", crate::hexrays::ctry_t)
    extern_cpp_type!("cthrow_t", crate::hexrays::cthrow_t)

    // idalib
    generate!("open_database")
    generate!("close_database")

    generate!("make_signatures")
    generate!("enable_console_messages")
    generate!("set_screen_ea")

    // segment
    generate!("segment_t")
    generate!("lock_segment")
    generate!("getseg")
    generate!("getnseg")
    generate!("get_segm_qty")
    generate!("get_segm_by_name")

    generate!("SEG_NORM")
    generate!("SEG_XTRN")
    generate!("SEG_CODE")
    generate!("SEG_DATA")
    generate!("SEG_IMP")
    generate!("SEG_GRP")
    generate!("SEG_NULL")
    generate!("SEG_UNDF")
    generate!("SEG_BSS")
    generate!("SEG_ABSSYM")
    generate!("SEG_COMM")
    generate!("SEG_IMEM")
    generate!("SEG_MAX_SEGTYPE_CODE")

    generate!("saAbs")
    generate!("saRelByte")
    generate!("saRelWord")
    generate!("saRelPara")
    generate!("saRelPage")
    generate!("saRelDble")
    generate!("saRel4K")
    generate!("saGroup")
    generate!("saRel32Bytes")
    generate!("saRel64Bytes")
    generate!("saRelQword")
    generate!("saRel128Bytes")
    generate!("saRel512Bytes")
    generate!("saRel1024Bytes")
    generate!("saRel2048Bytes")
    generate!("saRel_MAX_ALIGN_CODE")

    generate!("SEGPERM_EXEC")
    generate!("SEGPERM_WRITE")
    generate!("SEGPERM_READ")
    generate!("SEGPERM_MAXVAL")

    // ua (we use insn_t, op_t, etc. from pod)
    generate!("decode_insn")

    extern_cpp_type!("insn_t", crate::pod::insn_t)
    extern_cpp_type!("op_t", crate::pod::op_t)

    generate_pod!("optype_t")

    generate!("o_void")
    generate!("o_reg")
    generate!("o_mem")
    generate!("o_phrase")
    generate!("o_displ")
    generate!("o_imm")
    generate!("o_far")
    generate!("o_near")
    generate!("o_idpspec0")
    generate!("o_idpspec1")
    generate!("o_idpspec2")
    generate!("o_idpspec3")
    generate!("o_idpspec4")
    generate!("o_idpspec5")

    generate!("dt_byte")
    generate!("dt_word")
    generate!("dt_dword")
    generate!("dt_float")
    generate!("dt_double")
    generate!("dt_tbyte")
    generate!("dt_packreal")
    generate!("dt_qword")
    generate!("dt_byte16")
    generate!("dt_code")
    generate!("dt_void")
    generate!("dt_fword")
    generate!("dt_bitfild")
    generate!("dt_string")
    generate!("dt_unicode")
    generate!("dt_ldbl")
    generate!("dt_byte32")
    generate!("dt_byte64")
    generate!("dt_half")

    // xref
    generate_pod!("xrefblk_t")

    // NOTE: autocxx fails to generate methods on xrefblk_t...
    generate!("xrefblk_t_first_from")
    generate!("xrefblk_t_next_from")
    generate!("xrefblk_t_first_to")
    generate!("xrefblk_t_next_to")

    generate!("XREF_ALL")
    generate!("XREF_FAR")
    generate!("XREF_DATA")

    generate!("cref_t")
    generate!("dref_t")

    generate!("XREF_USER")
    generate!("XREF_TAIL")
    generate!("XREF_BASE")
    generate!("XREF_MASK")
    generate!("XREF_PASTEND")

    generate!("has_external_refs")

    // comments
    generate!("set_cmt")
    generate!("append_cmt")

    // strings
    generate!("build_strlist")
    generate!("clear_strlist")
    generate!("get_strlist_qty")

    // loader
    generate!("plugin_t")
    generate!("find_plugin")
    generate!("run_plugin")

    generate!("PLUGIN_MOD")
    generate!("PLUGIN_DRAW")
    generate!("PLUGIN_SEG")
    generate!("PLUGIN_UNL")
    generate!("PLUGIN_HIDE")
    generate!("PLUGIN_DBG")
    generate!("PLUGIN_PROC")
    generate!("PLUGIN_FIX")
    generate!("PLUGIN_MULTI")
    generate!("PLUGIN_SCRIPTED")

    // nalt
    generate!("retrieve_input_file_md5")
    generate!("retrieve_input_file_sha256")
    generate!("retrieve_input_file_size")

    // name(s)
    generate!("get_nlist_idx")
    generate!("get_nlist_size")
    generate!("get_nlist_ea")
    generate!("get_nlist_name")
    generate!("is_in_nlist")
    generate!("is_public_name")
    generate!("is_weak_name")
}

pub mod hexrays {
    use std::mem;

    use thiserror::Error;

    // NOTE: we don't export it; ideally this conversion should exist in idalib (not -sys), but it
    // having the conversion here gives us a cleaner interface.
    use super::ffi::merror_t;

    #[derive(Debug, Error)]
    #[error("{desc}")]
    pub struct HexRaysError {
        code: HexRaysErrorCode,
        addr: u64,
        desc: String,
    }

    impl HexRaysError {
        pub fn code(&self) -> HexRaysErrorCode {
            self.code
        }

        pub fn address(&self) -> u64 {
            self.addr
        }

        pub fn reason(&self) -> &str {
            &self.desc
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum HexRaysErrorCode {
        Ok,
        Block,
        Internal,
        Insn,
        Mem,
        BadBlock,
        BadSp,
        Prolog,
        Switch,
        Exception,
        HugeStack,
        LVars,
        Bitness,
        BadCall,
        BadFrame,
        UnknownType,
        BadIDB,
        SizeOf,
        Redo,
        Cancelled,
        RecursionDepth,
        Overlap,
        PartInitVar,
        Complex,
        License,
        Only32,
        Only64,
        Busy,
        FarPtr,
        Extern,
        FuncSize,
        BadRanges,
        BadArch,
        DelaySlot,
        Stop,
        Cloud,
        Loop,
        Unknown,
    }

    impl HexRaysErrorCode {
        pub fn is_ok(&self) -> bool {
            matches!(self, Self::Ok | Self::Block)
        }

        pub fn is_err(&self) -> bool {
            !self.is_ok()
        }
    }

    impl From<merror_t> for HexRaysErrorCode {
        fn from(value: merror_t) -> Self {
            match value {
                merror_t::MERR_OK => Self::Ok,
                merror_t::MERR_BLOCK => Self::Block,
                merror_t::MERR_INTERR => Self::Internal,
                merror_t::MERR_INSN => Self::Insn,
                merror_t::MERR_MEM => Self::Mem,
                merror_t::MERR_BADBLK => Self::BadBlock,
                merror_t::MERR_BADSP => Self::BadSp,
                merror_t::MERR_PROLOG => Self::Prolog,
                merror_t::MERR_SWITCH => Self::Switch,
                merror_t::MERR_EXCEPTION => Self::Exception,
                merror_t::MERR_HUGESTACK => Self::HugeStack,
                merror_t::MERR_LVARS => Self::LVars,
                merror_t::MERR_BITNESS => Self::Bitness,
                merror_t::MERR_BADCALL => Self::BadCall,
                merror_t::MERR_BADFRAME => Self::BadFrame,
                merror_t::MERR_UNKTYPE => Self::UnknownType,
                merror_t::MERR_BADIDB => Self::BadIDB,
                merror_t::MERR_SIZEOF => Self::SizeOf,
                merror_t::MERR_REDO => Self::Redo,
                merror_t::MERR_CANCELED => Self::Cancelled,
                merror_t::MERR_RECDEPTH => Self::RecursionDepth,
                merror_t::MERR_OVERLAP => Self::Overlap,
                merror_t::MERR_PARTINIT => Self::PartInitVar,
                merror_t::MERR_COMPLEX => Self::Complex,
                merror_t::MERR_LICENSE => Self::License,
                merror_t::MERR_ONLY32 => Self::Only32,
                merror_t::MERR_ONLY64 => Self::Only64,
                merror_t::MERR_BUSY => Self::Busy,
                merror_t::MERR_FARPTR => Self::FarPtr,
                merror_t::MERR_EXTERN => Self::Extern,
                merror_t::MERR_FUNCSIZE => Self::FuncSize,
                merror_t::MERR_BADRANGES => Self::BadRanges,
                merror_t::MERR_BADARCH => Self::BadArch,
                merror_t::MERR_DSLOT => Self::DelaySlot,
                merror_t::MERR_STOP => Self::Stop,
                merror_t::MERR_CLOUD => Self::Cloud,
                merror_t::MERR_LOOP => Self::Loop,
                _ => Self::Unknown,
            }
        }
    }

    mod __impl {
        #![allow(non_camel_case_types)]
        #![allow(non_upper_case_globals)]
        #![allow(unused)]
        #![allow(rustdoc::all)]

        include!(concat!(env!("OUT_DIR"), "/hexrays.rs"));
    }

    pub use __impl::{cblock_t, cexpr_t, cfunc_t, cinsn_t, citem_t, cswitch_t, cthrow_t, ctry_t};

    pub use super::ffi::{
        carg_t, carglist_t, cfuncptr_t, init_hexrays_plugin, term_hexrays_plugin,
    };

    pub use super::ffix::{
        carglist_iter,
        // Iterators
        cblock_iter,
        idalib_hexrays_carg_formal_type_str,
        idalib_hexrays_carg_is_vararg,
        idalib_hexrays_carglist_at,
        // carglist_t operations
        idalib_hexrays_carglist_count,
        idalib_hexrays_carglist_iter,
        idalib_hexrays_carglist_iter_next,
        // cinsn_t operations
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
        // Expression type checking (new)
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
        // cfunc_t additional operations (new)
        idalib_hexrays_cfunc_boundaries_count,
        idalib_hexrays_cfunc_del_orphan_cmts,
        idalib_hexrays_cfunc_eamap_count,
        idalib_hexrays_cfunc_entry_ea,
        idalib_hexrays_cfunc_find_by_ea,
        idalib_hexrays_cfunc_find_label,
        idalib_hexrays_cfunc_find_lvar_by_name,
        // Tree navigation (new)
        idalib_hexrays_cfunc_find_parent_of,
        idalib_hexrays_cfunc_has_orphan_cmts,
        idalib_hexrays_cfunc_hdrlines,
        idalib_hexrays_cfunc_lvar_at,
        idalib_hexrays_cfunc_lvars_count,
        idalib_hexrays_cfunc_lvars_iter,
        idalib_hexrays_cfunc_maturity,
        // Microcode operations
        idalib_hexrays_cfunc_mba,
        idalib_hexrays_cfunc_print_dcl,
        // cfunc_t operations
        idalib_hexrays_cfunc_pseudocode,
        idalib_hexrays_cfunc_pseudocode_line_at,
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
        idalib_hexrays_cinsn_cblock,
        idalib_hexrays_cinsn_cexpr,
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
        // Switch case operations
        idalib_hexrays_cinsn_switch_case_body,
        idalib_hexrays_cinsn_switch_case_value_at,
        idalib_hexrays_cinsn_switch_case_values_count,
        idalib_hexrays_cinsn_switch_cases_count,
        idalib_hexrays_cinsn_switch_expr,
        idalib_hexrays_cinsn_throw_expr,
        // Try/catch operations
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
        // Additional citem operations (new)
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
        // ctype_t constants
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
        idalib_hexrays_decompile_func,
        // merror_t helpers (new)
        idalib_hexrays_get_merror_desc,
        idalib_hexrays_get_signed_mcode,
        idalib_hexrays_get_unsigned_mcode,
        idalib_hexrays_has_cached_cfunc,
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
        // lvar_t modifications (new)
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
        idalib_hexrays_mba_has_calls,
        idalib_hexrays_mba_has_glbopt,
        idalib_hexrays_mba_has_passregs,
        idalib_hexrays_mba_is_cmnstk,
        idalib_hexrays_mba_is_pattern,
        idalib_hexrays_mba_is_short,
        idalib_hexrays_mba_is_thunk,
        idalib_hexrays_mba_maturity,
        idalib_hexrays_mba_minea,
        idalib_hexrays_mba_qty,
        idalib_hexrays_mba_returns_float,
        // mba_t additional operations (new)
        idalib_hexrays_mba_stacksize,
        idalib_hexrays_mblock_end,
        idalib_hexrays_mblock_flags,
        idalib_hexrays_mblock_head,
        idalib_hexrays_mblock_insn_count,
        idalib_hexrays_mblock_is_branch,
        // mblock_t predicates (new)
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
        // mblock_t operations
        idalib_hexrays_mblock_serial,
        idalib_hexrays_mblock_start,
        idalib_hexrays_mblock_succ,
        idalib_hexrays_mblock_tail,
        idalib_hexrays_mblock_type,
        // mcode_t helpers (new)
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
        idalib_hexrays_merr_badarch,
        idalib_hexrays_merr_badblk,
        idalib_hexrays_merr_badcall,
        idalib_hexrays_merr_badframe,
        idalib_hexrays_merr_badidb,
        idalib_hexrays_merr_badranges,
        idalib_hexrays_merr_badsp,
        idalib_hexrays_merr_bitness,
        idalib_hexrays_merr_busy,
        idalib_hexrays_merr_canceled,
        idalib_hexrays_merr_complex,
        idalib_hexrays_merr_exception,
        idalib_hexrays_merr_funcsize,
        idalib_hexrays_merr_hugestack,
        idalib_hexrays_merr_insn,
        idalib_hexrays_merr_interr,
        idalib_hexrays_merr_license,
        idalib_hexrays_merr_lvars,
        idalib_hexrays_merr_mem,
        idalib_hexrays_merr_ok,
        idalib_hexrays_merr_overlap,
        idalib_hexrays_merr_partinit,
        idalib_hexrays_merr_prolog,
        idalib_hexrays_merr_recdepth,
        idalib_hexrays_merr_redo,
        idalib_hexrays_merr_sizeof,
        idalib_hexrays_merr_switch,
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
        // minsn_t predicates (new)
        idalib_hexrays_minsn_is_tailcall,
        idalib_hexrays_minsn_is_unknown_call,
        idalib_hexrays_minsn_is_wild_match,
        // minsn_t additional operations (new)
        idalib_hexrays_minsn_l,
        idalib_hexrays_minsn_modifies_d,
        idalib_hexrays_minsn_next,
        idalib_hexrays_minsn_nexti,
        // minsn_t operations
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
        idalib_hexrays_mop_d,
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
        idalib_hexrays_mop_str,
        // mop_t operations (new)
        idalib_hexrays_mop_type,
        idalib_hexrays_mop_v,
        // mop_t type constants (new)
        idalib_hexrays_mop_z,
        idalib_hexrays_must_mcode_close_block,
        // mcode_t relation helpers (new)
        idalib_hexrays_negate_mcode_relation,
        // Operator helpers
        idalib_hexrays_negated_relation,
        idalib_hexrays_save_user_cmts_ea,
        idalib_hexrays_save_user_iflags_ea,
        // User data management (new)
        idalib_hexrays_save_user_labels_ea,
        idalib_hexrays_save_user_numforms_ea,
        idalib_hexrays_save_user_unions_ea,
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

    unsafe impl cxx::ExternType for cfunc_t {
        type Id = cxx::type_id!("cfunc_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for citem_t {
        type Id = cxx::type_id!("citem_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for cinsn_t {
        type Id = cxx::type_id!("cinsn_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for cexpr_t {
        type Id = cxx::type_id!("cexpr_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for cblock_t {
        type Id = cxx::type_id!("cblock_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for cswitch_t {
        type Id = cxx::type_id!("cswitch_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for cthrow_t {
        type Id = cxx::type_id!("cthrow_t");
        type Kind = cxx::kind::Opaque;
    }

    unsafe impl cxx::ExternType for ctry_t {
        type Id = cxx::type_id!("ctry_t");
        type Kind = cxx::kind::Opaque;
    }

    pub unsafe fn decompile_func(
        f: *mut super::ffi::func_t,
        all_blocks: bool,
    ) -> Result<cxx::UniquePtr<cfuncptr_t>, HexRaysError> {
        let mut flags = __impl::DECOMP_NO_WAIT | __impl::DECOMP_NO_CACHE;

        if all_blocks {
            flags |= __impl::DECOMP_ALL_BLKS;
        }

        let mut failure = super::ffix::hexrays_error_t::default();
        let result = super::ffix::idalib_hexrays_decompile_func(
            f,
            &mut failure as *mut _,
            (flags as i32).into(),
        );

        let code = HexRaysErrorCode::from(mem::transmute::<i32, merror_t>(failure.code));

        if result.is_null() || code.is_err() {
            Err(HexRaysError {
                addr: failure.addr,
                code,
                desc: failure.desc,
            })
        } else {
            Ok(result)
        }
    }
}

pub mod idp {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/idp.rs"));
}

pub mod inf {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/inf.rs"));

    unsafe impl cxx::ExternType for compiler_info_t {
        type Id = cxx::type_id!("compiler_info_t");
        type Kind = cxx::kind::Trivial;
    }

    pub use super::ffi::filetype_t;
    pub use super::ffix::{
        idalib_inf_abi_set_by_user, idalib_inf_allow_non_matched_ops, idalib_inf_allow_sigmulti,
        idalib_inf_append_sigcmt, idalib_inf_big_arg_align, idalib_inf_check_manual_ops,
        idalib_inf_check_unicode_strlits, idalib_inf_coagulate_code, idalib_inf_coagulate_data,
        idalib_inf_compress_idb, idalib_inf_create_all_xrefs, idalib_inf_create_func_from_call,
        idalib_inf_create_func_from_ptr, idalib_inf_create_func_tails,
        idalib_inf_create_jump_tables, idalib_inf_create_off_on_dref,
        idalib_inf_create_off_using_fixup, idalib_inf_create_strlit_on_xref,
        idalib_inf_data_offset, idalib_inf_dbg_no_store_path, idalib_inf_decode_fpp,
        idalib_inf_final_pass, idalib_inf_full_sp_ana, idalib_inf_gen_assume, idalib_inf_gen_lzero,
        idalib_inf_gen_null, idalib_inf_gen_org, idalib_inf_gen_tryblks, idalib_inf_get_abibits,
        idalib_inf_get_af, idalib_inf_get_af2, idalib_inf_get_app_bitness,
        idalib_inf_get_appcall_options, idalib_inf_get_apptype, idalib_inf_get_asmtype,
        idalib_inf_get_baseaddr, idalib_inf_get_bin_prefix_size, idalib_inf_get_cc,
        idalib_inf_get_cc_cm, idalib_inf_get_cc_defalign, idalib_inf_get_cc_id,
        idalib_inf_get_cc_size_b, idalib_inf_get_cc_size_e, idalib_inf_get_cc_size_i,
        idalib_inf_get_cc_size_l, idalib_inf_get_cc_size_ldbl, idalib_inf_get_cc_size_ll,
        idalib_inf_get_cc_size_s, idalib_inf_get_cmt_indent, idalib_inf_get_cmtflg,
        idalib_inf_get_database_change_count, idalib_inf_get_datatypes, idalib_inf_get_demnames,
        idalib_inf_get_filetype, idalib_inf_get_genflags, idalib_inf_get_highoff,
        idalib_inf_get_indent, idalib_inf_get_lenxref, idalib_inf_get_lflags,
        idalib_inf_get_limiter, idalib_inf_get_listnames, idalib_inf_get_long_demnames,
        idalib_inf_get_lowoff, idalib_inf_get_main, idalib_inf_get_margin,
        idalib_inf_get_max_autoname_len, idalib_inf_get_max_ea, idalib_inf_get_maxref,
        idalib_inf_get_min_ea, idalib_inf_get_nametype, idalib_inf_get_netdelta,
        idalib_inf_get_omax_ea, idalib_inf_get_omin_ea, idalib_inf_get_ostype,
        idalib_inf_get_outflags, idalib_inf_get_prefflag, idalib_inf_get_privrange,
        idalib_inf_get_privrange_end_ea, idalib_inf_get_privrange_start_ea,
        idalib_inf_get_procname, idalib_inf_get_refcmtnum, idalib_inf_get_short_demnames,
        idalib_inf_get_specsegs, idalib_inf_get_start_cs, idalib_inf_get_start_ea,
        idalib_inf_get_start_ip, idalib_inf_get_start_sp, idalib_inf_get_start_ss,
        idalib_inf_get_strlit_break, idalib_inf_get_strlit_flags, idalib_inf_get_strlit_pref,
        idalib_inf_get_strlit_sernum, idalib_inf_get_strlit_zeroes, idalib_inf_get_strtype,
        idalib_inf_get_type_xrefnum, idalib_inf_get_version, idalib_inf_get_xrefflag,
        idalib_inf_get_xrefnum, idalib_inf_guess_func_type, idalib_inf_handle_eh,
        idalib_inf_handle_rtti, idalib_inf_hide_comments, idalib_inf_hide_libfuncs,
        idalib_inf_huge_arg_align, idalib_inf_is_16bit, idalib_inf_is_32bit_exactly,
        idalib_inf_is_32bit_or_higher, idalib_inf_is_64bit, idalib_inf_is_auto_enabled,
        idalib_inf_is_be, idalib_inf_is_dll, idalib_inf_is_flat_off32, idalib_inf_is_graph_view,
        idalib_inf_is_hard_float, idalib_inf_is_kernel_mode, idalib_inf_is_limiter_empty,
        idalib_inf_is_limiter_thick, idalib_inf_is_limiter_thin, idalib_inf_is_mem_aligned4,
        idalib_inf_is_snapshot, idalib_inf_is_wide_high_byte_first, idalib_inf_line_pref_with_seg,
        idalib_inf_loading_idc, idalib_inf_macros_enabled, idalib_inf_map_stkargs,
        idalib_inf_mark_code, idalib_inf_merge_strlits, idalib_inf_no_store_user_info,
        idalib_inf_noflow_to_data, idalib_inf_noret_ana, idalib_inf_op_offset, idalib_inf_pack_idb,
        idalib_inf_pack_stkargs, idalib_inf_prefix_show_funcoff, idalib_inf_prefix_show_segaddr,
        idalib_inf_prefix_show_stack, idalib_inf_prefix_truncate_opcode_bytes,
        idalib_inf_propagate_regargs, idalib_inf_propagate_stkargs, idalib_inf_readonly_idb,
        idalib_inf_rename_jumpfunc, idalib_inf_rename_nullsub, idalib_inf_set_show_all_comments,
        idalib_inf_set_show_hidden_funcs, idalib_inf_set_show_hidden_insns,
        idalib_inf_set_show_hidden_segms, idalib_inf_should_create_stkvars,
        idalib_inf_should_trace_sp, idalib_inf_show_all_comments, idalib_inf_show_auto,
        idalib_inf_show_hidden_funcs, idalib_inf_show_hidden_insns, idalib_inf_show_hidden_segms,
        idalib_inf_show_line_pref, idalib_inf_show_repeatables, idalib_inf_show_src_linnum,
        idalib_inf_show_void, idalib_inf_show_xref_fncoff, idalib_inf_show_xref_seg,
        idalib_inf_show_xref_tmarks, idalib_inf_show_xref_val, idalib_inf_stack_ldbl,
        idalib_inf_stack_varargs, idalib_inf_strlit_autocmt, idalib_inf_strlit_name_bit,
        idalib_inf_strlit_names, idalib_inf_strlit_savecase, idalib_inf_strlit_serial_names,
        idalib_inf_test_mode, idalib_inf_trace_flow, idalib_inf_truncate_on_del,
        idalib_inf_unicode_strlits, idalib_inf_use_allasm, idalib_inf_use_flirt,
        idalib_inf_use_gcc_layout,
    };
}

pub mod pod {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/pod.rs"));

    unsafe impl cxx::ExternType for op_t {
        type Id = cxx::type_id!("op_t");
        type Kind = cxx::kind::Trivial;
    }

    unsafe impl cxx::ExternType for insn_t {
        type Id = cxx::type_id!("insn_t");
        type Kind = cxx::kind::Trivial;
    }
}

#[cxx::bridge]
mod ffix {
    #[derive(Default)]
    struct hexrays_error_t {
        code: i32,
        addr: u64,
        desc: String,
    }

    unsafe extern "C++" {
        include!("autocxxgen_ffi.h");
        include!("idalib.hpp");

        include!("types.h");
        include!("auto_extras.h");
        include!("bookmarks_extras.h");
        include!("bytes_extras.h");
        include!("comments_extras.h");
        include!("entry_extras.h");
        include!("fixup_extras.h");
        include!("frame_extras.h");
        include!("func_extras.h");
        include!("funcs_extras.h");
        include!("hexrays_extras.h");
        include!("idalib_extras.h");
        include!("inf_extras.h");
        include!("kernwin_extras.h");
        include!("lines_extras.h");
        include!("loader_extras.h");
        include!("nalt_extras.h");
        include!("name_extras.h");
        include!("netnode_extras.h");
        include!("offset_extras.h");
        include!("ph_extras.h");
        include!("problems_extras.h");
        include!("segm_extras.h");
        include!("search_extras.h");
        include!("segregs_extras.h");
        include!("strings_extras.h");
        include!("tryblks_extras.h");
        include!("typeinf_extras.h");
        include!("xref_extras.h");

        type c_short = autocxx::c_short;
        type c_int = autocxx::c_int;
        type c_uint = autocxx::c_uint;
        type c_longlong = autocxx::c_longlong;
        type c_ulonglong = autocxx::c_ulonglong;

        // type comp_t = super::ffi::comp_t;
        type compiler_info_t = super::inf::compiler_info_t;
        // type cm_t = super::ffi::cm_t;
        type filetype_t = super::ffi::filetype_t;
        type range_t = super::ffi::range_t;
        // type uval_t = autocxx::c_ulonglong;

        type func_t = super::ffi::func_t;
        type processor_t = super::ffi::processor_t;
        type qflow_chart_t = super::ffi::qflow_chart_t;
        type qbasic_block_t = super::ffi::qbasic_block_t;
        type segment_t = super::ffi::segment_t;

        // cfuncptr_t
        type qrefcnt_t_cfunc_t_AutocxxConcrete = super::ffi::qrefcnt_t_cfunc_t_AutocxxConcrete;
        type cfunc_t = super::hexrays::cfunc_t;
        type cblock_t = super::hexrays::cblock_t;
        type cinsn_t = super::hexrays::cinsn_t;
        type citem_t = super::hexrays::citem_t;

        type cblock_iter;
        type lvars_iter;
        type carglist_iter;
        type cexpr_t = super::hexrays::cexpr_t;
        type carg_t = super::ffi::carg_t;
        type carglist_t = super::ffi::carglist_t;
        type lvar_t;
        type mba_t;
        type mblock_t;
        type minsn_t;
        type mop_t;

        type plugin_t = super::ffi::plugin_t;

        unsafe fn init_library(argc: c_int, argv: *mut *mut c_char) -> c_int;

        unsafe fn idalib_open_database_quiet(
            argc: c_int,
            argv: *const *const c_char,
            auto_analysis: bool,
        ) -> c_int;
        unsafe fn idalib_check_license() -> bool;
        unsafe fn idalib_get_license_id(id: &mut [u8; 6]) -> bool;

        // NOTE: we can't use uval_t here due to it resolving to c_ulonglong,
        // which causes `verify_extern_type` to fail...
        unsafe fn idalib_entry_name(e: c_ulonglong) -> Result<String>;

        unsafe fn idalib_func_flags(f: *const func_t) -> u64;
        unsafe fn idalib_func_name(f: *const func_t) -> Result<String>;
        unsafe fn idalib_get_func_cmt(f: *const func_t, rptble: bool) -> Result<String>;
        unsafe fn idalib_set_func_cmt(f: *const func_t, cmt: *const c_char, rptble: bool) -> bool;

        unsafe fn idalib_func_flow_chart(
            f: *mut func_t,
            flags: c_int,
        ) -> Result<UniquePtr<qflow_chart_t>>;

        unsafe fn idalib_hexrays_cfuncptr_inner(
            f: *const qrefcnt_t_cfunc_t_AutocxxConcrete,
        ) -> *mut cfunc_t;
        unsafe fn idalib_hexrays_cfunc_pseudocode(f: *mut cfunc_t) -> String;

        unsafe fn idalib_hexrays_decompile_func(
            f: *mut func_t,
            err: *mut hexrays_error_t,
            flags: c_int,
        ) -> UniquePtr<qrefcnt_t_cfunc_t_AutocxxConcrete>;

        unsafe fn idalib_hexrays_cblock_iter(b: *mut cblock_t) -> UniquePtr<cblock_iter>;
        unsafe fn idalib_hexrays_cblock_iter_next(slf: Pin<&mut cblock_iter>) -> *mut cinsn_t;
        unsafe fn idalib_hexrays_cblock_len(b: *mut cblock_t) -> usize;

        // cfunc_t operations
        unsafe fn idalib_hexrays_cfunc_entry_ea(f: *const cfunc_t) -> u64;
        unsafe fn idalib_hexrays_cfunc_maturity(f: *const cfunc_t) -> c_int;
        unsafe fn idalib_hexrays_cfunc_hdrlines(f: *const cfunc_t) -> c_int;
        unsafe fn idalib_hexrays_cfunc_print_dcl(f: *const cfunc_t) -> String;
        unsafe fn idalib_hexrays_cfunc_type_str(f: *const cfunc_t) -> String;
        unsafe fn idalib_hexrays_cfunc_lvars_count(f: *mut cfunc_t) -> usize;
        unsafe fn idalib_hexrays_cfunc_lvars_iter(f: *mut cfunc_t) -> UniquePtr<lvars_iter>;
        unsafe fn idalib_hexrays_lvars_iter_next(it: Pin<&mut lvars_iter>) -> *mut lvar_t;
        unsafe fn idalib_hexrays_cfunc_argidx_count(f: *const cfunc_t) -> usize;
        unsafe fn idalib_hexrays_cfunc_argidx_at(f: *const cfunc_t, i: usize) -> c_int;
        unsafe fn idalib_hexrays_cfunc_stkoff_delta(f: *mut cfunc_t) -> i64;
        unsafe fn idalib_hexrays_cfunc_has_orphan_cmts(f: *const cfunc_t) -> bool;
        unsafe fn idalib_hexrays_cfunc_del_orphan_cmts(f: *mut cfunc_t) -> c_int;
        unsafe fn idalib_hexrays_cfunc_warnings_count(f: *mut cfunc_t) -> usize;
        unsafe fn idalib_hexrays_cfunc_warning_at(f: *mut cfunc_t, idx: usize) -> String;
        unsafe fn idalib_hexrays_cfunc_warning_ea_at(f: *mut cfunc_t, idx: usize) -> u64;
        unsafe fn idalib_hexrays_cfunc_find_label(f: *mut cfunc_t, label: c_int) -> *mut citem_t;
        unsafe fn idalib_hexrays_cfunc_remove_unused_labels(f: *mut cfunc_t);
        unsafe fn idalib_hexrays_cfunc_refresh(f: *mut cfunc_t);
        unsafe fn idalib_hexrays_cfunc_save_user_cmts(f: *const cfunc_t);
        unsafe fn idalib_hexrays_cfunc_save_user_labels(f: *const cfunc_t);
        unsafe fn idalib_hexrays_cfunc_save_user_numforms(f: *const cfunc_t);
        unsafe fn idalib_hexrays_cfunc_save_user_iflags(f: *const cfunc_t);
        unsafe fn idalib_hexrays_cfunc_save_user_unions(f: *const cfunc_t);

        // citem_t operations
        unsafe fn idalib_hexrays_citem_ea(item: *const citem_t) -> u64;
        unsafe fn idalib_hexrays_citem_op(item: *const citem_t) -> c_int;
        unsafe fn idalib_hexrays_citem_is_expr(item: *const citem_t) -> bool;
        unsafe fn idalib_hexrays_citem_label_num(item: *const citem_t) -> c_int;
        unsafe fn idalib_hexrays_citem_contains_label(item: *const citem_t) -> bool;
        unsafe fn idalib_hexrays_citem_print(item: *const citem_t) -> String;
        unsafe fn idalib_hexrays_ctype_name(op: c_int) -> String;

        // cexpr_t operations
        unsafe fn idalib_hexrays_cexpr_type_str(e: *const cexpr_t) -> String;
        unsafe fn idalib_hexrays_cexpr_type_size(e: *const cexpr_t) -> usize;
        unsafe fn idalib_hexrays_cexpr_type_is_signed(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_unsigned(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_ptr(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_array(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_struct(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_union(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_float(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_x(e: *mut cexpr_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cexpr_y(e: *mut cexpr_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cexpr_z(e: *mut cexpr_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cexpr_numval(e: *const cexpr_t) -> u64;
        unsafe fn idalib_hexrays_cexpr_obj_ea(e: *const cexpr_t) -> u64;
        unsafe fn idalib_hexrays_cexpr_var_idx(e: *const cexpr_t) -> c_int;
        unsafe fn idalib_hexrays_cexpr_str(e: *const cexpr_t) -> String;
        unsafe fn idalib_hexrays_cexpr_helper(e: *const cexpr_t) -> String;
        unsafe fn idalib_hexrays_cexpr_member_offset(e: *const cexpr_t) -> u32;
        unsafe fn idalib_hexrays_cexpr_ptrsize(e: *const cexpr_t) -> c_int;
        unsafe fn idalib_hexrays_cexpr_call_args(e: *mut cexpr_t) -> *mut carglist_t;
        unsafe fn idalib_hexrays_cexpr_is_nice(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_is_call(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_exflags(e: *const cexpr_t) -> u32;
        unsafe fn idalib_hexrays_cexpr_is_cstr(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_is_fpop(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_is_undef_val(e: *const cexpr_t) -> bool;

        // cinsn_t operations
        unsafe fn idalib_hexrays_cinsn_cblock(s: *mut cinsn_t) -> *mut cblock_t;
        unsafe fn idalib_hexrays_cinsn_cexpr(s: *mut cinsn_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cinsn_if_cond(s: *mut cinsn_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cinsn_if_then(s: *mut cinsn_t) -> *mut cinsn_t;
        unsafe fn idalib_hexrays_cinsn_if_else(s: *mut cinsn_t) -> *mut cinsn_t;
        unsafe fn idalib_hexrays_cinsn_for_init(s: *mut cinsn_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cinsn_for_cond(s: *mut cinsn_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cinsn_for_step(s: *mut cinsn_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cinsn_for_body(s: *mut cinsn_t) -> *mut cinsn_t;
        unsafe fn idalib_hexrays_cinsn_while_cond(s: *mut cinsn_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cinsn_while_body(s: *mut cinsn_t) -> *mut cinsn_t;
        unsafe fn idalib_hexrays_cinsn_do_cond(s: *mut cinsn_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cinsn_do_body(s: *mut cinsn_t) -> *mut cinsn_t;
        unsafe fn idalib_hexrays_cinsn_return_expr(s: *mut cinsn_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cinsn_goto_label(s: *mut cinsn_t) -> c_int;
        unsafe fn idalib_hexrays_cinsn_switch_expr(s: *mut cinsn_t) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cinsn_switch_cases_count(s: *mut cinsn_t) -> usize;
        unsafe fn idalib_hexrays_cinsn_is_ordinary_flow(s: *const cinsn_t) -> bool;
        unsafe fn idalib_hexrays_cinsn_contains_free_break(s: *const cinsn_t) -> bool;
        unsafe fn idalib_hexrays_cinsn_contains_free_continue(s: *const cinsn_t) -> bool;

        // carglist_t operations
        unsafe fn idalib_hexrays_carglist_count(args: *const carglist_t) -> usize;
        unsafe fn idalib_hexrays_carglist_at(args: *mut carglist_t, idx: usize) -> *mut carg_t;
        unsafe fn idalib_hexrays_carglist_iter(args: *mut carglist_t) -> UniquePtr<carglist_iter>;
        unsafe fn idalib_hexrays_carglist_iter_next(it: Pin<&mut carglist_iter>) -> *mut carg_t;
        unsafe fn idalib_hexrays_carg_formal_type_str(arg: *const carg_t) -> String;
        unsafe fn idalib_hexrays_carg_is_vararg(arg: *const carg_t) -> bool;

        // lvar_t operations
        unsafe fn idalib_hexrays_lvar_name(v: *const lvar_t) -> String;
        unsafe fn idalib_hexrays_lvar_type_str(v: *const lvar_t) -> String;
        unsafe fn idalib_hexrays_lvar_cmt(v: *const lvar_t) -> String;
        unsafe fn idalib_hexrays_lvar_width(v: *const lvar_t) -> c_int;
        unsafe fn idalib_hexrays_lvar_defblk(v: *const lvar_t) -> c_int;
        unsafe fn idalib_hexrays_lvar_defea(v: *const lvar_t) -> u64;
        unsafe fn idalib_hexrays_lvar_is_used(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_is_typed(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_has_nice_name(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_has_user_name(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_has_user_type(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_is_arg(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_is_result(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_is_thisarg(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_is_fake(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_is_overlapped(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_is_floating(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_is_stk_var(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_is_reg_var(v: *const lvar_t) -> bool;
        unsafe fn idalib_hexrays_lvar_get_reg(v: *const lvar_t) -> c_int;
        unsafe fn idalib_hexrays_lvar_get_stkoff(v: *const lvar_t) -> i64;
        unsafe fn idalib_hexrays_lvar_is_used_byref(v: *const lvar_t) -> bool;

        // Operator helpers
        unsafe fn idalib_hexrays_negated_relation(op: c_int) -> c_int;
        unsafe fn idalib_hexrays_swapped_relation(op: c_int) -> c_int;
        unsafe fn idalib_hexrays_is_binary_op(op: c_int) -> bool;
        unsafe fn idalib_hexrays_is_unary_op(op: c_int) -> bool;
        unsafe fn idalib_hexrays_is_relational_op(op: c_int) -> bool;
        unsafe fn idalib_hexrays_is_assignment_op(op: c_int) -> bool;
        unsafe fn idalib_hexrays_is_loop_op(op: c_int) -> bool;
        unsafe fn idalib_hexrays_is_lvalue_op(op: c_int) -> bool;
        unsafe fn idalib_hexrays_is_commutative_op(op: c_int) -> bool;

        // Microcode operations
        unsafe fn idalib_hexrays_cfunc_mba(f: *mut cfunc_t) -> *mut mba_t;
        unsafe fn idalib_hexrays_mba_qty(mba: *const mba_t) -> c_int;
        unsafe fn idalib_hexrays_mba_entry_ea(mba: *const mba_t) -> u64;
        unsafe fn idalib_hexrays_mba_maturity(mba: *const mba_t) -> c_int;
        unsafe fn idalib_hexrays_mba_get_mblock(mba: *mut mba_t, n: c_int) -> *mut mblock_t;

        // mblock_t operations
        unsafe fn idalib_hexrays_mblock_serial(blk: *const mblock_t) -> c_int;
        unsafe fn idalib_hexrays_mblock_start(blk: *const mblock_t) -> u64;
        unsafe fn idalib_hexrays_mblock_end(blk: *const mblock_t) -> u64;
        unsafe fn idalib_hexrays_mblock_type(blk: *const mblock_t) -> c_int;
        unsafe fn idalib_hexrays_mblock_npred(blk: *const mblock_t) -> c_int;
        unsafe fn idalib_hexrays_mblock_nsucc(blk: *const mblock_t) -> c_int;
        unsafe fn idalib_hexrays_mblock_pred(blk: *const mblock_t, n: c_int) -> c_int;
        unsafe fn idalib_hexrays_mblock_succ(blk: *const mblock_t, n: c_int) -> c_int;
        unsafe fn idalib_hexrays_mblock_head(blk: *mut mblock_t) -> *mut minsn_t;
        unsafe fn idalib_hexrays_mblock_tail(blk: *mut mblock_t) -> *mut minsn_t;

        // minsn_t operations
        unsafe fn idalib_hexrays_minsn_opcode(insn: *const minsn_t) -> c_int;
        unsafe fn idalib_hexrays_minsn_ea(insn: *const minsn_t) -> u64;
        unsafe fn idalib_hexrays_minsn_next(insn: *mut minsn_t) -> *mut minsn_t;
        unsafe fn idalib_hexrays_minsn_prev(insn: *mut minsn_t) -> *mut minsn_t;
        unsafe fn idalib_hexrays_minsn_dstr(insn: *const minsn_t) -> String;
        unsafe fn idalib_hexrays_mcode_name(opcode: c_int) -> String;

        // Cache management
        unsafe fn idalib_hexrays_mark_cfunc_dirty(ea: u64, close_views: bool) -> bool;
        unsafe fn idalib_hexrays_clear_cached_cfuncs();
        unsafe fn idalib_hexrays_has_cached_cfunc(ea: u64) -> bool;

        // Decompilation flags
        unsafe fn idalib_hexrays_decomp_no_wait() -> c_int;
        unsafe fn idalib_hexrays_decomp_no_cache() -> c_int;
        unsafe fn idalib_hexrays_decomp_no_frame() -> c_int;
        unsafe fn idalib_hexrays_decomp_warnings() -> c_int;
        unsafe fn idalib_hexrays_decomp_all_blks() -> c_int;

        // ctype_t constants - expressions
        unsafe fn idalib_hexrays_cot_empty() -> c_int;
        unsafe fn idalib_hexrays_cot_comma() -> c_int;
        unsafe fn idalib_hexrays_cot_asg() -> c_int;
        unsafe fn idalib_hexrays_cot_asgbor() -> c_int;
        unsafe fn idalib_hexrays_cot_asgxor() -> c_int;
        unsafe fn idalib_hexrays_cot_asgband() -> c_int;
        unsafe fn idalib_hexrays_cot_asgadd() -> c_int;
        unsafe fn idalib_hexrays_cot_asgsub() -> c_int;
        unsafe fn idalib_hexrays_cot_asgmul() -> c_int;
        unsafe fn idalib_hexrays_cot_asgsshr() -> c_int;
        unsafe fn idalib_hexrays_cot_asgushr() -> c_int;
        unsafe fn idalib_hexrays_cot_asgshl() -> c_int;
        unsafe fn idalib_hexrays_cot_asgsdiv() -> c_int;
        unsafe fn idalib_hexrays_cot_asgudiv() -> c_int;
        unsafe fn idalib_hexrays_cot_asgsmod() -> c_int;
        unsafe fn idalib_hexrays_cot_asgumod() -> c_int;
        unsafe fn idalib_hexrays_cot_tern() -> c_int;
        unsafe fn idalib_hexrays_cot_lor() -> c_int;
        unsafe fn idalib_hexrays_cot_land() -> c_int;
        unsafe fn idalib_hexrays_cot_bor() -> c_int;
        unsafe fn idalib_hexrays_cot_xor() -> c_int;
        unsafe fn idalib_hexrays_cot_band() -> c_int;
        unsafe fn idalib_hexrays_cot_eq() -> c_int;
        unsafe fn idalib_hexrays_cot_ne() -> c_int;
        unsafe fn idalib_hexrays_cot_sge() -> c_int;
        unsafe fn idalib_hexrays_cot_uge() -> c_int;
        unsafe fn idalib_hexrays_cot_sle() -> c_int;
        unsafe fn idalib_hexrays_cot_ule() -> c_int;
        unsafe fn idalib_hexrays_cot_sgt() -> c_int;
        unsafe fn idalib_hexrays_cot_ugt() -> c_int;
        unsafe fn idalib_hexrays_cot_slt() -> c_int;
        unsafe fn idalib_hexrays_cot_ult() -> c_int;
        unsafe fn idalib_hexrays_cot_sshr() -> c_int;
        unsafe fn idalib_hexrays_cot_ushr() -> c_int;
        unsafe fn idalib_hexrays_cot_shl() -> c_int;
        unsafe fn idalib_hexrays_cot_add() -> c_int;
        unsafe fn idalib_hexrays_cot_sub() -> c_int;
        unsafe fn idalib_hexrays_cot_mul() -> c_int;
        unsafe fn idalib_hexrays_cot_sdiv() -> c_int;
        unsafe fn idalib_hexrays_cot_udiv() -> c_int;
        unsafe fn idalib_hexrays_cot_smod() -> c_int;
        unsafe fn idalib_hexrays_cot_umod() -> c_int;
        unsafe fn idalib_hexrays_cot_fadd() -> c_int;
        unsafe fn idalib_hexrays_cot_fsub() -> c_int;
        unsafe fn idalib_hexrays_cot_fmul() -> c_int;
        unsafe fn idalib_hexrays_cot_fdiv() -> c_int;
        unsafe fn idalib_hexrays_cot_fneg() -> c_int;
        unsafe fn idalib_hexrays_cot_neg() -> c_int;
        unsafe fn idalib_hexrays_cot_cast() -> c_int;
        unsafe fn idalib_hexrays_cot_lnot() -> c_int;
        unsafe fn idalib_hexrays_cot_bnot() -> c_int;
        unsafe fn idalib_hexrays_cot_ptr() -> c_int;
        unsafe fn idalib_hexrays_cot_ref() -> c_int;
        unsafe fn idalib_hexrays_cot_postinc() -> c_int;
        unsafe fn idalib_hexrays_cot_postdec() -> c_int;
        unsafe fn idalib_hexrays_cot_preinc() -> c_int;
        unsafe fn idalib_hexrays_cot_predec() -> c_int;
        unsafe fn idalib_hexrays_cot_call() -> c_int;
        unsafe fn idalib_hexrays_cot_idx() -> c_int;
        unsafe fn idalib_hexrays_cot_memref() -> c_int;
        unsafe fn idalib_hexrays_cot_memptr() -> c_int;
        unsafe fn idalib_hexrays_cot_num() -> c_int;
        unsafe fn idalib_hexrays_cot_fnum() -> c_int;
        unsafe fn idalib_hexrays_cot_str() -> c_int;
        unsafe fn idalib_hexrays_cot_obj() -> c_int;
        unsafe fn idalib_hexrays_cot_var() -> c_int;
        unsafe fn idalib_hexrays_cot_insn() -> c_int;
        unsafe fn idalib_hexrays_cot_sizeof() -> c_int;
        unsafe fn idalib_hexrays_cot_helper() -> c_int;
        unsafe fn idalib_hexrays_cot_type() -> c_int;
        unsafe fn idalib_hexrays_cot_last() -> c_int;

        // ctype_t constants - statements
        unsafe fn idalib_hexrays_cit_empty() -> c_int;
        unsafe fn idalib_hexrays_cit_block() -> c_int;
        unsafe fn idalib_hexrays_cit_expr() -> c_int;
        unsafe fn idalib_hexrays_cit_if() -> c_int;
        unsafe fn idalib_hexrays_cit_for() -> c_int;
        unsafe fn idalib_hexrays_cit_while() -> c_int;
        unsafe fn idalib_hexrays_cit_do() -> c_int;
        unsafe fn idalib_hexrays_cit_switch() -> c_int;
        unsafe fn idalib_hexrays_cit_break() -> c_int;
        unsafe fn idalib_hexrays_cit_continue() -> c_int;
        unsafe fn idalib_hexrays_cit_return() -> c_int;
        unsafe fn idalib_hexrays_cit_goto() -> c_int;
        unsafe fn idalib_hexrays_cit_asm() -> c_int;
        unsafe fn idalib_hexrays_cit_try() -> c_int;
        unsafe fn idalib_hexrays_cit_throw() -> c_int;

        // Switch case operations (new) - use cinsn_t* and indices instead of ccases_t/ccase_t
        unsafe fn idalib_hexrays_cinsn_switch_case_values_count(
            s: *mut cinsn_t,
            case_idx: usize,
        ) -> usize;
        unsafe fn idalib_hexrays_cinsn_switch_case_value_at(
            s: *mut cinsn_t,
            case_idx: usize,
            val_idx: usize,
        ) -> u64;
        unsafe fn idalib_hexrays_cinsn_switch_case_body(
            s: *mut cinsn_t,
            case_idx: usize,
        ) -> *mut cinsn_t;

        // Try/catch operations (new)
        unsafe fn idalib_hexrays_cinsn_try_first_stmt(s: *mut cinsn_t) -> *mut cinsn_t;
        unsafe fn idalib_hexrays_ctry_catches_count(s: *const cinsn_t) -> usize;
        unsafe fn idalib_hexrays_ctry_catch_at(s: *mut cinsn_t, idx: usize) -> *mut cinsn_t;
        unsafe fn idalib_hexrays_ctry_catch_expr_count(s: *const cinsn_t, idx: usize) -> usize;
        unsafe fn idalib_hexrays_ctry_catch_is_catch_all(s: *const cinsn_t, idx: usize) -> bool;
        unsafe fn idalib_hexrays_ctry_catch_obj_expr(
            s: *mut cinsn_t,
            catch_idx: usize,
            expr_idx: usize,
        ) -> *mut cexpr_t;
        unsafe fn idalib_hexrays_cinsn_throw_expr(s: *mut cinsn_t) -> *mut cexpr_t;

        // Tree navigation (new)
        unsafe fn idalib_hexrays_cfunc_find_parent_of(
            f: *mut cfunc_t,
            item: *const citem_t,
        ) -> *mut citem_t;
        unsafe fn idalib_hexrays_cfunc_find_by_ea(f: *mut cfunc_t, ea: u64) -> *mut citem_t;
        unsafe fn idalib_hexrays_cinsn_contains_expr(s: *const cinsn_t, e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_is_child_of(
            e: *const cexpr_t,
            parent: *const citem_t,
        ) -> bool;
        unsafe fn idalib_hexrays_cexpr_requires_lvalue(
            parent: *const cexpr_t,
            child: *const cexpr_t,
        ) -> bool;
        unsafe fn idalib_hexrays_cexpr_equal_effect(a: *const cexpr_t, b: *const cexpr_t) -> bool;

        // lvar_t modifications (new)
        unsafe fn idalib_hexrays_lvar_set_type(
            f: *mut cfunc_t,
            v: *mut lvar_t,
            type_str: *const c_char,
        ) -> bool;
        unsafe fn idalib_hexrays_lvar_set_name(
            f: *mut cfunc_t,
            v: *mut lvar_t,
            name: *const c_char,
        ) -> bool;
        unsafe fn idalib_hexrays_lvar_set_cmt(v: *mut lvar_t, cmt: *const c_char);
        unsafe fn idalib_hexrays_cfunc_lvar_at(f: *mut cfunc_t, idx: usize) -> *mut lvar_t;
        unsafe fn idalib_hexrays_cfunc_find_lvar_by_name(
            f: *mut cfunc_t,
            name: *const c_char,
        ) -> *mut lvar_t;

        // mop_t operations (new)
        unsafe fn idalib_hexrays_mop_type(op: *const mop_t) -> c_int;
        unsafe fn idalib_hexrays_mop_size(op: *const mop_t) -> c_int;
        unsafe fn idalib_hexrays_mop_reg(op: *const mop_t) -> c_int;
        unsafe fn idalib_hexrays_mop_nnn_value(op: *const mop_t) -> u64;
        unsafe fn idalib_hexrays_mop_addr_target(op: *const mop_t) -> *const mop_t;
        unsafe fn idalib_hexrays_mop_stkoff(op: *const mop_t) -> i64;
        unsafe fn idalib_hexrays_mop_lvar_idx(op: *const mop_t) -> c_int;
        unsafe fn idalib_hexrays_mop_glbaddr(op: *const mop_t) -> u64;
        unsafe fn idalib_hexrays_mop_is_number(op: *const mop_t) -> bool;
        unsafe fn idalib_hexrays_mop_is_reg(op: *const mop_t) -> bool;
        unsafe fn idalib_hexrays_mop_is_stk(op: *const mop_t) -> bool;
        unsafe fn idalib_hexrays_mop_is_lvar(op: *const mop_t) -> bool;
        unsafe fn idalib_hexrays_mop_is_glb(op: *const mop_t) -> bool;
        unsafe fn idalib_hexrays_mop_is_addr(op: *const mop_t) -> bool;
        unsafe fn idalib_hexrays_mop_is_insn(op: *const mop_t) -> bool;
        unsafe fn idalib_hexrays_mop_insn(op: *mut mop_t) -> *mut minsn_t;
        unsafe fn idalib_hexrays_mop_dstr(op: *const mop_t) -> String;

        // minsn_t additional operations (new)
        unsafe fn idalib_hexrays_minsn_l(insn: *mut minsn_t) -> *mut mop_t;
        unsafe fn idalib_hexrays_minsn_r(insn: *mut minsn_t) -> *mut mop_t;
        unsafe fn idalib_hexrays_minsn_d(insn: *mut minsn_t) -> *mut mop_t;
        unsafe fn idalib_hexrays_minsn_is_call(insn: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_jump(insn: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_cond(insn: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_modifies_d(insn: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_find_call(
            insn: *mut minsn_t,
            with_helpers: bool,
        ) -> *mut minsn_t;

        // mba_t additional operations (new)
        unsafe fn idalib_hexrays_mba_stacksize(mba: *const mba_t) -> i64;
        unsafe fn idalib_hexrays_mba_argidx_size(mba: *const mba_t) -> c_int;
        unsafe fn idalib_hexrays_mba_minea(mba: *const mba_t) -> u64;
        unsafe fn idalib_hexrays_mba_first_epilog_ea(mba: *const mba_t) -> u64;
        unsafe fn idalib_hexrays_mba_is_thunk(mba: *const mba_t) -> bool;
        unsafe fn idalib_hexrays_mba_is_short(mba: *const mba_t) -> bool;
        unsafe fn idalib_hexrays_mba_has_passregs(mba: *const mba_t) -> bool;

        // cfunc_t additional operations (new)
        unsafe fn idalib_hexrays_cfunc_boundaries_count(f: *mut cfunc_t) -> usize;
        unsafe fn idalib_hexrays_cfunc_pseudocode_line_count(f: *mut cfunc_t) -> usize;
        unsafe fn idalib_hexrays_cfunc_pseudocode_line_at(f: *mut cfunc_t, idx: usize) -> String;
        unsafe fn idalib_hexrays_cfunc_pseudocode_line_tagged_at(
            f: *mut cfunc_t,
            idx: usize,
        ) -> String;
        unsafe fn idalib_hexrays_cfunc_eamap_count(f: *mut cfunc_t) -> usize;

        // User data management (new)
        unsafe fn idalib_hexrays_save_user_labels_ea(ea: u64);
        unsafe fn idalib_hexrays_save_user_cmts_ea(ea: u64);
        unsafe fn idalib_hexrays_save_user_numforms_ea(ea: u64);
        unsafe fn idalib_hexrays_save_user_iflags_ea(ea: u64);
        unsafe fn idalib_hexrays_save_user_unions_ea(ea: u64);

        // Expression type checking (new)
        unsafe fn idalib_hexrays_cexpr_type_is_funcptr(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_pvoid(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_void(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_bool(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_enum(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_const(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_is_volatile(e: *const cexpr_t) -> bool;
        unsafe fn idalib_hexrays_cexpr_type_ptr_depth(e: *const cexpr_t) -> c_int;
        unsafe fn idalib_hexrays_cexpr_type_array_size(e: *const cexpr_t) -> i64;
        unsafe fn idalib_hexrays_cexpr_type_pointed_str(e: *const cexpr_t) -> String;

        // Additional citem operations (new)
        unsafe fn idalib_hexrays_citem_index_in_parent(
            f: *const cfunc_t,
            item: *const citem_t,
        ) -> c_int;

        // mcode_t helpers (new)
        unsafe fn idalib_hexrays_mcode_category(mcode: c_int) -> c_int;
        unsafe fn idalib_hexrays_mcode_modifies_mem(mcode: c_int) -> bool;
        unsafe fn idalib_hexrays_mcode_reads_mem(mcode: c_int) -> bool;
        unsafe fn idalib_hexrays_mcode_is_comparison(mcode: c_int) -> bool;
        unsafe fn idalib_hexrays_mcode_is_arithmetic(mcode: c_int) -> bool;
        unsafe fn idalib_hexrays_mcode_is_bitwise(mcode: c_int) -> bool;

        // mop_t type constants (new)
        unsafe fn idalib_hexrays_mop_z() -> c_int;
        unsafe fn idalib_hexrays_mop_r() -> c_int;
        unsafe fn idalib_hexrays_mop_n() -> c_int;
        unsafe fn idalib_hexrays_mop_str() -> c_int;
        unsafe fn idalib_hexrays_mop_d() -> c_int;
        unsafe fn idalib_hexrays_mop_S() -> c_int;
        unsafe fn idalib_hexrays_mop_v() -> c_int;
        unsafe fn idalib_hexrays_mop_b() -> c_int;
        unsafe fn idalib_hexrays_mop_f() -> c_int;
        unsafe fn idalib_hexrays_mop_l() -> c_int;
        unsafe fn idalib_hexrays_mop_a() -> c_int;
        unsafe fn idalib_hexrays_mop_h() -> c_int;
        unsafe fn idalib_hexrays_mop_c() -> c_int;
        unsafe fn idalib_hexrays_mop_fn() -> c_int;
        unsafe fn idalib_hexrays_mop_p() -> c_int;
        unsafe fn idalib_hexrays_mop_sc() -> c_int;

        // Additional minsn_t predicates
        unsafe fn idalib_hexrays_minsn_is_tailcall(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_fpinsn(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_assert(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_persistent(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_combined(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_farcall(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_cleaning_pop(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_propagatable(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_wild_match(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_was_noret_icall(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_multimov(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_is_unknown_call(m: *const minsn_t) -> bool;
        unsafe fn idalib_hexrays_minsn_iprops(m: *const minsn_t) -> c_int;

        // Additional mblock_t operations
        unsafe fn idalib_hexrays_mblock_is_call_block(blk: *const mblock_t) -> bool;
        unsafe fn idalib_hexrays_mblock_is_unknown_call(blk: *const mblock_t) -> bool;
        unsafe fn idalib_hexrays_mblock_is_nway(blk: *const mblock_t) -> bool;
        unsafe fn idalib_hexrays_mblock_is_branch(blk: *const mblock_t) -> bool;
        unsafe fn idalib_hexrays_mblock_is_simple_goto_block(blk: *const mblock_t) -> bool;
        unsafe fn idalib_hexrays_mblock_is_simple_jcnd_block(blk: *const mblock_t) -> bool;
        unsafe fn idalib_hexrays_mblock_is_empty(blk: *const mblock_t) -> bool;
        unsafe fn idalib_hexrays_mblock_flags(blk: *const mblock_t) -> u32;
        unsafe fn idalib_hexrays_mblock_is_fake(blk: *const mblock_t) -> bool;
        unsafe fn idalib_hexrays_mblock_is_goto_target(blk: *const mblock_t) -> bool;
        unsafe fn idalib_hexrays_mblock_is_noret(blk: *const mblock_t) -> bool;
        unsafe fn idalib_hexrays_mblock_insn_count(blk: *const mblock_t) -> usize;

        // mcode_t relation helpers
        unsafe fn idalib_hexrays_negate_mcode_relation(mcode: c_int) -> c_int;
        unsafe fn idalib_hexrays_swap_mcode_relation(mcode: c_int) -> c_int;
        unsafe fn idalib_hexrays_get_signed_mcode(mcode: c_int) -> c_int;
        unsafe fn idalib_hexrays_get_unsigned_mcode(mcode: c_int) -> c_int;
        unsafe fn idalib_hexrays_mcode_modifies_d(mcode: c_int) -> bool;
        unsafe fn idalib_hexrays_is_mcode_propagatable(mcode: c_int) -> bool;
        unsafe fn idalib_hexrays_must_mcode_close_block(
            mcode: c_int,
            including_calls: bool,
        ) -> bool;
        unsafe fn idalib_hexrays_mcode_is_set(mcode: c_int) -> bool;
        unsafe fn idalib_hexrays_mcode_is_jcc(mcode: c_int) -> bool;
        unsafe fn idalib_hexrays_mcode_is_fpu(mcode: c_int) -> bool;
        unsafe fn idalib_hexrays_mcode_is_call(mcode: c_int) -> bool;
        unsafe fn idalib_hexrays_mcode_is_jump(mcode: c_int) -> bool;
        unsafe fn idalib_hexrays_mcode_is_ret(mcode: c_int) -> bool;

        // Additional mba_t operations
        unsafe fn idalib_hexrays_mba_has_calls(mba: *const mba_t) -> bool;
        unsafe fn idalib_hexrays_mba_is_pattern(mba: *const mba_t) -> bool;
        unsafe fn idalib_hexrays_mba_returns_float(mba: *const mba_t) -> bool;
        unsafe fn idalib_hexrays_mba_has_glbopt(mba: *const mba_t) -> bool;
        unsafe fn idalib_hexrays_mba_is_cmnstk(mba: *const mba_t) -> bool;
        unsafe fn idalib_hexrays_mba_flags(mba: *const mba_t) -> u32;
        unsafe fn idalib_hexrays_mba_final_maturity() -> c_int;

        // merror_t helpers
        unsafe fn idalib_hexrays_get_merror_desc(code: c_int) -> String;
        unsafe fn idalib_hexrays_merr_ok() -> c_int;
        unsafe fn idalib_hexrays_merr_interr() -> c_int;
        unsafe fn idalib_hexrays_merr_insn() -> c_int;
        unsafe fn idalib_hexrays_merr_mem() -> c_int;
        unsafe fn idalib_hexrays_merr_badblk() -> c_int;
        unsafe fn idalib_hexrays_merr_badsp() -> c_int;
        unsafe fn idalib_hexrays_merr_prolog() -> c_int;
        unsafe fn idalib_hexrays_merr_switch() -> c_int;
        unsafe fn idalib_hexrays_merr_exception() -> c_int;
        unsafe fn idalib_hexrays_merr_hugestack() -> c_int;
        unsafe fn idalib_hexrays_merr_lvars() -> c_int;
        unsafe fn idalib_hexrays_merr_bitness() -> c_int;
        unsafe fn idalib_hexrays_merr_badcall() -> c_int;
        unsafe fn idalib_hexrays_merr_badframe() -> c_int;
        unsafe fn idalib_hexrays_merr_badidb() -> c_int;
        unsafe fn idalib_hexrays_merr_sizeof() -> c_int;
        unsafe fn idalib_hexrays_merr_redo() -> c_int;
        unsafe fn idalib_hexrays_merr_canceled() -> c_int;
        unsafe fn idalib_hexrays_merr_recdepth() -> c_int;
        unsafe fn idalib_hexrays_merr_overlap() -> c_int;
        unsafe fn idalib_hexrays_merr_partinit() -> c_int;
        unsafe fn idalib_hexrays_merr_complex() -> c_int;
        unsafe fn idalib_hexrays_merr_license() -> c_int;
        unsafe fn idalib_hexrays_merr_busy() -> c_int;
        unsafe fn idalib_hexrays_merr_funcsize() -> c_int;
        unsafe fn idalib_hexrays_merr_badranges() -> c_int;
        unsafe fn idalib_hexrays_merr_badarch() -> c_int;

        // minsn_t iteration helpers
        unsafe fn idalib_hexrays_minsn_nexti(m: *const minsn_t) -> *mut minsn_t;
        unsafe fn idalib_hexrays_minsn_previ(m: *const minsn_t) -> *mut minsn_t;

        unsafe fn idalib_inf_get_version() -> u16;
        unsafe fn idalib_inf_get_genflags() -> u16;
        unsafe fn idalib_inf_is_auto_enabled() -> bool;
        unsafe fn idalib_inf_use_allasm() -> bool;
        unsafe fn idalib_inf_loading_idc() -> bool;
        unsafe fn idalib_inf_no_store_user_info() -> bool;
        unsafe fn idalib_inf_readonly_idb() -> bool;
        unsafe fn idalib_inf_check_manual_ops() -> bool;
        unsafe fn idalib_inf_allow_non_matched_ops() -> bool;
        unsafe fn idalib_inf_is_graph_view() -> bool;
        unsafe fn idalib_inf_get_lflags() -> u32;
        unsafe fn idalib_inf_decode_fpp() -> bool;
        unsafe fn idalib_inf_is_32bit_or_higher() -> bool;
        unsafe fn idalib_inf_is_32bit_exactly() -> bool;
        unsafe fn idalib_inf_is_16bit() -> bool;
        unsafe fn idalib_inf_is_64bit() -> bool;
        unsafe fn idalib_inf_is_dll() -> bool;
        unsafe fn idalib_inf_is_flat_off32() -> bool;
        unsafe fn idalib_inf_is_be() -> bool;
        unsafe fn idalib_inf_is_wide_high_byte_first() -> bool;
        unsafe fn idalib_inf_dbg_no_store_path() -> bool;
        unsafe fn idalib_inf_is_snapshot() -> bool;
        unsafe fn idalib_inf_pack_idb() -> bool;
        unsafe fn idalib_inf_compress_idb() -> bool;
        unsafe fn idalib_inf_is_kernel_mode() -> bool;
        unsafe fn idalib_inf_get_app_bitness() -> c_uint;
        unsafe fn idalib_inf_get_database_change_count() -> u32;
        unsafe fn idalib_inf_get_filetype() -> filetype_t;
        unsafe fn idalib_inf_get_ostype() -> u16;
        unsafe fn idalib_inf_get_apptype() -> u16;
        unsafe fn idalib_inf_get_asmtype() -> u8;
        unsafe fn idalib_inf_get_specsegs() -> u8;
        unsafe fn idalib_inf_get_af() -> u32;
        unsafe fn idalib_inf_trace_flow() -> bool;
        unsafe fn idalib_inf_mark_code() -> bool;
        unsafe fn idalib_inf_create_jump_tables() -> bool;
        unsafe fn idalib_inf_noflow_to_data() -> bool;
        unsafe fn idalib_inf_create_all_xrefs() -> bool;
        unsafe fn idalib_inf_create_func_from_ptr() -> bool;
        unsafe fn idalib_inf_create_func_from_call() -> bool;
        unsafe fn idalib_inf_create_func_tails() -> bool;
        unsafe fn idalib_inf_should_create_stkvars() -> bool;
        unsafe fn idalib_inf_propagate_stkargs() -> bool;
        unsafe fn idalib_inf_propagate_regargs() -> bool;
        unsafe fn idalib_inf_should_trace_sp() -> bool;
        unsafe fn idalib_inf_full_sp_ana() -> bool;
        unsafe fn idalib_inf_noret_ana() -> bool;
        unsafe fn idalib_inf_guess_func_type() -> bool;
        unsafe fn idalib_inf_truncate_on_del() -> bool;
        unsafe fn idalib_inf_create_strlit_on_xref() -> bool;
        unsafe fn idalib_inf_check_unicode_strlits() -> bool;
        unsafe fn idalib_inf_create_off_using_fixup() -> bool;
        unsafe fn idalib_inf_create_off_on_dref() -> bool;
        unsafe fn idalib_inf_op_offset() -> bool;
        unsafe fn idalib_inf_data_offset() -> bool;
        unsafe fn idalib_inf_use_flirt() -> bool;
        unsafe fn idalib_inf_append_sigcmt() -> bool;
        unsafe fn idalib_inf_allow_sigmulti() -> bool;
        unsafe fn idalib_inf_hide_libfuncs() -> bool;
        unsafe fn idalib_inf_rename_jumpfunc() -> bool;
        unsafe fn idalib_inf_rename_nullsub() -> bool;
        unsafe fn idalib_inf_coagulate_data() -> bool;
        unsafe fn idalib_inf_coagulate_code() -> bool;
        unsafe fn idalib_inf_final_pass() -> bool;
        unsafe fn idalib_inf_get_af2() -> u32;
        unsafe fn idalib_inf_handle_eh() -> bool;
        unsafe fn idalib_inf_handle_rtti() -> bool;
        unsafe fn idalib_inf_macros_enabled() -> bool;
        unsafe fn idalib_inf_merge_strlits() -> bool;
        unsafe fn idalib_inf_get_baseaddr() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_ss() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_cs() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_ip() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_sp() -> c_ulonglong;
        unsafe fn idalib_inf_get_main() -> c_ulonglong;
        unsafe fn idalib_inf_get_min_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_max_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_omin_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_omax_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_lowoff() -> c_ulonglong;
        unsafe fn idalib_inf_get_highoff() -> c_ulonglong;
        unsafe fn idalib_inf_get_maxref() -> c_ulonglong;
        unsafe fn idalib_inf_get_netdelta() -> c_longlong;
        unsafe fn idalib_inf_get_xrefnum() -> u8;
        unsafe fn idalib_inf_get_type_xrefnum() -> u8;
        unsafe fn idalib_inf_get_refcmtnum() -> u8;
        unsafe fn idalib_inf_get_xrefflag() -> u8;
        unsafe fn idalib_inf_show_xref_seg() -> bool;
        unsafe fn idalib_inf_show_xref_tmarks() -> bool;
        unsafe fn idalib_inf_show_xref_fncoff() -> bool;
        unsafe fn idalib_inf_show_xref_val() -> bool;
        unsafe fn idalib_inf_get_max_autoname_len() -> u16;
        unsafe fn idalib_inf_get_nametype() -> c_char;
        unsafe fn idalib_inf_get_short_demnames() -> u32;
        unsafe fn idalib_inf_get_long_demnames() -> u32;
        unsafe fn idalib_inf_get_demnames() -> u8;
        unsafe fn idalib_inf_get_listnames() -> u8;
        unsafe fn idalib_inf_get_indent() -> u8;
        unsafe fn idalib_inf_get_cmt_indent() -> u8;
        unsafe fn idalib_inf_get_margin() -> u16;
        unsafe fn idalib_inf_get_lenxref() -> u16;
        unsafe fn idalib_inf_get_outflags() -> u32;
        unsafe fn idalib_inf_show_void() -> bool;
        unsafe fn idalib_inf_show_auto() -> bool;
        unsafe fn idalib_inf_gen_null() -> bool;
        unsafe fn idalib_inf_show_line_pref() -> bool;
        unsafe fn idalib_inf_line_pref_with_seg() -> bool;
        unsafe fn idalib_inf_gen_lzero() -> bool;
        unsafe fn idalib_inf_gen_org() -> bool;
        unsafe fn idalib_inf_gen_assume() -> bool;
        unsafe fn idalib_inf_gen_tryblks() -> bool;
        unsafe fn idalib_inf_get_cmtflg() -> u8;
        unsafe fn idalib_inf_show_repeatables() -> bool;
        unsafe fn idalib_inf_show_all_comments() -> bool;
        unsafe fn idalib_inf_set_show_all_comments() -> bool;
        unsafe fn idalib_inf_hide_comments() -> bool;
        unsafe fn idalib_inf_show_src_linnum() -> bool;
        unsafe fn idalib_inf_test_mode() -> bool;
        unsafe fn idalib_inf_show_hidden_insns() -> bool;
        unsafe fn idalib_inf_set_show_hidden_insns() -> bool;
        unsafe fn idalib_inf_show_hidden_funcs() -> bool;
        unsafe fn idalib_inf_set_show_hidden_funcs() -> bool;
        unsafe fn idalib_inf_show_hidden_segms() -> bool;
        unsafe fn idalib_inf_set_show_hidden_segms() -> bool;
        unsafe fn idalib_inf_get_limiter() -> u8;
        unsafe fn idalib_inf_is_limiter_thin() -> bool;
        unsafe fn idalib_inf_is_limiter_thick() -> bool;
        unsafe fn idalib_inf_is_limiter_empty() -> bool;
        unsafe fn idalib_inf_get_bin_prefix_size() -> c_short;
        unsafe fn idalib_inf_get_prefflag() -> u8;
        unsafe fn idalib_inf_prefix_show_segaddr() -> bool;
        unsafe fn idalib_inf_prefix_show_funcoff() -> bool;
        unsafe fn idalib_inf_prefix_show_stack() -> bool;
        unsafe fn idalib_inf_prefix_truncate_opcode_bytes() -> bool;
        unsafe fn idalib_inf_get_strlit_flags() -> u8;
        unsafe fn idalib_inf_strlit_names() -> bool;
        unsafe fn idalib_inf_strlit_name_bit() -> bool;
        unsafe fn idalib_inf_strlit_serial_names() -> bool;
        unsafe fn idalib_inf_unicode_strlits() -> bool;
        unsafe fn idalib_inf_strlit_autocmt() -> bool;
        unsafe fn idalib_inf_strlit_savecase() -> bool;
        unsafe fn idalib_inf_get_strlit_break() -> u8;
        unsafe fn idalib_inf_get_strlit_zeroes() -> c_char;
        unsafe fn idalib_inf_get_strtype() -> i32;
        unsafe fn idalib_inf_get_strlit_sernum() -> c_ulonglong;
        unsafe fn idalib_inf_get_datatypes() -> c_ulonglong;
        unsafe fn idalib_inf_get_abibits() -> u32;
        unsafe fn idalib_inf_is_mem_aligned4() -> bool;
        unsafe fn idalib_inf_pack_stkargs() -> bool;
        unsafe fn idalib_inf_big_arg_align() -> bool;
        unsafe fn idalib_inf_stack_ldbl() -> bool;
        unsafe fn idalib_inf_stack_varargs() -> bool;
        unsafe fn idalib_inf_is_hard_float() -> bool;
        unsafe fn idalib_inf_abi_set_by_user() -> bool;
        unsafe fn idalib_inf_use_gcc_layout() -> bool;
        unsafe fn idalib_inf_map_stkargs() -> bool;
        unsafe fn idalib_inf_huge_arg_align() -> bool;
        unsafe fn idalib_inf_get_appcall_options() -> u32;
        unsafe fn idalib_inf_get_privrange_start_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_privrange_end_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_cc_id() -> u8;
        unsafe fn idalib_inf_get_cc_cm() -> u8;
        unsafe fn idalib_inf_get_cc_size_i() -> u8;
        unsafe fn idalib_inf_get_cc_size_b() -> u8;
        unsafe fn idalib_inf_get_cc_size_e() -> u8;
        unsafe fn idalib_inf_get_cc_defalign() -> u8;
        unsafe fn idalib_inf_get_cc_size_s() -> u8;
        unsafe fn idalib_inf_get_cc_size_l() -> u8;
        unsafe fn idalib_inf_get_cc_size_ll() -> u8;
        unsafe fn idalib_inf_get_cc_size_ldbl() -> u8;
        unsafe fn idalib_inf_get_procname() -> String;
        unsafe fn idalib_inf_get_strlit_pref() -> String;
        unsafe fn idalib_inf_get_cc(out: *mut compiler_info_t) -> bool;
        unsafe fn idalib_inf_get_privrange(out: *mut range_t) -> bool;

        unsafe fn idalib_ph_id(ph: *const processor_t) -> i32;
        unsafe fn idalib_ph_short_name(ph: *const processor_t) -> String;
        unsafe fn idalib_ph_long_name(ph: *const processor_t) -> String;
        unsafe fn idalib_is_thumb_at(ph: *const processor_t, ea: c_ulonglong) -> bool;

        unsafe fn idalib_qflow_graph_getn_block(
            f: *const qflow_chart_t,
            n: usize,
        ) -> *const qbasic_block_t;

        unsafe fn idalib_qbasic_block_succs<'a>(b: *const qbasic_block_t) -> &'a [c_int];
        unsafe fn idalib_qbasic_block_preds<'a>(b: *const qbasic_block_t) -> &'a [c_int];

        unsafe fn idalib_segm_name(s: *const segment_t) -> Result<String>;
        unsafe fn idalib_segm_bytes(s: *const segment_t, buf: &mut Vec<u8>) -> Result<usize>;
        unsafe fn idalib_segm_align(s: *const segment_t) -> u8;
        unsafe fn idalib_segm_perm(s: *const segment_t) -> u8;
        unsafe fn idalib_segm_bitness(s: *const segment_t) -> u8;
        unsafe fn idalib_segm_type(s: *const segment_t) -> u8;

        unsafe fn idalib_get_cmt(ea: c_ulonglong, rptble: bool) -> String;

        unsafe fn idalib_bookmarks_t_mark(
            ea: c_ulonglong,
            index: c_uint,
            desc: *const c_char,
        ) -> u32;
        unsafe fn idalib_bookmarks_t_get_desc(index: c_uint) -> String;
        unsafe fn idalib_bookmarks_t_get(index: c_uint) -> c_ulonglong;
        unsafe fn idalib_bookmarks_t_erase(index: c_uint) -> bool;
        unsafe fn idalib_bookmarks_t_size() -> u32;
        unsafe fn idalib_bookmarks_t_find_index(ea: c_ulonglong) -> u32;

        unsafe fn idalib_find_text(ea: c_ulonglong, text: *const c_char) -> c_ulonglong;
        unsafe fn idalib_find_imm(ea: c_ulonglong, imm: c_uint) -> c_ulonglong;
        unsafe fn idalib_find_defined(ea: c_ulonglong) -> c_ulonglong;

        unsafe fn idalib_get_strlist_item_addr(index: usize) -> c_ulonglong;
        unsafe fn idalib_get_strlist_item_length(index: usize) -> usize;

        unsafe fn idalib_ea2str(ea: c_ulonglong) -> String;

        // bytes - reading
        unsafe fn idalib_get_byte(ea: c_ulonglong) -> u8;
        unsafe fn idalib_get_word(ea: c_ulonglong) -> u16;
        unsafe fn idalib_get_dword(ea: c_ulonglong) -> u32;
        unsafe fn idalib_get_qword(ea: c_ulonglong) -> u64;
        unsafe fn idalib_get_bytes(ea: c_ulonglong, buf: &mut Vec<u8>) -> Result<usize>;

        // bytes - patching
        unsafe fn idalib_patch_byte(ea: c_ulonglong, value: u8) -> bool;
        unsafe fn idalib_patch_word(ea: c_ulonglong, value: u16) -> bool;
        unsafe fn idalib_patch_dword(ea: c_ulonglong, value: u32) -> bool;
        unsafe fn idalib_patch_qword(ea: c_ulonglong, value: u64) -> bool;
        unsafe fn idalib_patch_bytes(ea: c_ulonglong, data: &[u8]);

        // bytes - original values
        unsafe fn idalib_get_original_byte(ea: c_ulonglong) -> u8;
        unsafe fn idalib_get_original_word(ea: c_ulonglong) -> u16;
        unsafe fn idalib_get_original_dword(ea: c_ulonglong) -> u32;
        unsafe fn idalib_get_original_qword(ea: c_ulonglong) -> u64;
        unsafe fn idalib_revert_byte(ea: c_ulonglong);

        // bytes - put (modify database)
        unsafe fn idalib_put_byte(ea: c_ulonglong, value: u8) -> bool;
        unsafe fn idalib_put_word(ea: c_ulonglong, value: u16);
        unsafe fn idalib_put_dword(ea: c_ulonglong, value: u32);
        unsafe fn idalib_put_qword(ea: c_ulonglong, value: u64);
        unsafe fn idalib_put_bytes(ea: c_ulonglong, data: &[u8]);

        // bytes - create data types
        unsafe fn idalib_del_items(ea: c_ulonglong, flags: c_int, nbytes: u64) -> bool;
        unsafe fn idalib_create_byte(ea: c_ulonglong, length: u64) -> bool;
        unsafe fn idalib_create_word(ea: c_ulonglong, length: u64) -> bool;
        unsafe fn idalib_create_dword(ea: c_ulonglong, length: u64) -> bool;
        unsafe fn idalib_create_qword(ea: c_ulonglong, length: u64) -> bool;
        unsafe fn idalib_create_float(ea: c_ulonglong, length: u64) -> bool;
        unsafe fn idalib_create_double(ea: c_ulonglong, length: u64) -> bool;

        // bytes - flags inspection
        unsafe fn idalib_is_mapped(ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_loaded(ea: c_ulonglong) -> bool;
        unsafe fn idalib_has_value(flags: u64) -> bool;
        unsafe fn idalib_is_byte(flags: u64) -> bool;
        unsafe fn idalib_is_word(flags: u64) -> bool;
        unsafe fn idalib_is_dword(flags: u64) -> bool;
        unsafe fn idalib_is_qword(flags: u64) -> bool;
        unsafe fn idalib_is_float(flags: u64) -> bool;
        unsafe fn idalib_is_double(flags: u64) -> bool;
        unsafe fn idalib_is_head(flags: u64) -> bool;
        unsafe fn idalib_is_tail(flags: u64) -> bool;
        unsafe fn idalib_is_unknown(flags: u64) -> bool;
        unsafe fn idalib_is_flow(flags: u64) -> bool;

        // bytes - item size/navigation
        unsafe fn idalib_get_item_size(ea: c_ulonglong) -> u64;
        unsafe fn idalib_get_item_end(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_item_head(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_next_addr(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_prev_addr(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_next_not_tail(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_prev_not_tail(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_next_unknown(ea: c_ulonglong, maxea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_prev_unknown(ea: c_ulonglong, minea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_next_that(ea: c_ulonglong, maxea: c_ulonglong, code: bool) -> c_ulonglong;
        unsafe fn idalib_prev_that(ea: c_ulonglong, minea: c_ulonglong, code: bool) -> c_ulonglong;

        unsafe fn idalib_get_input_file_path() -> String;

        unsafe fn idalib_plugin_version(p: *const plugin_t) -> u64;
        unsafe fn idalib_plugin_flags(p: *const plugin_t) -> u64;

        unsafe fn idalib_get_library_version(
            major: *mut c_int,
            minor: *mut c_int,
            build: *mut c_int,
        ) -> bool;

        // name operations
        unsafe fn idalib_set_name(ea: c_ulonglong, name: *const c_char, flags: c_int) -> bool;
        unsafe fn idalib_del_name(ea: c_ulonglong) -> bool;
        unsafe fn idalib_force_name(ea: c_ulonglong, name: *const c_char, flags: c_int) -> bool;
        unsafe fn idalib_get_name(ea: c_ulonglong) -> String;
        unsafe fn idalib_get_visible_name(ea: c_ulonglong) -> String;
        unsafe fn idalib_get_short_name(ea: c_ulonglong) -> String;
        unsafe fn idalib_get_long_name(ea: c_ulonglong) -> String;
        unsafe fn idalib_get_colored_name(ea: c_ulonglong) -> String;
        unsafe fn idalib_get_name_ea(from: c_ulonglong, name: *const c_char) -> c_ulonglong;
        unsafe fn idalib_demangle_name(name: *const c_char, disable_mask: u32) -> String;
        unsafe fn idalib_is_ident(name: *const c_char) -> bool;
        unsafe fn idalib_is_uname(name: *const c_char) -> bool;
        unsafe fn idalib_is_valid_typename(name: *const c_char) -> bool;
        unsafe fn idalib_make_name_public(ea: c_ulonglong);
        unsafe fn idalib_make_name_non_public(ea: c_ulonglong);
        unsafe fn idalib_make_name_weak(ea: c_ulonglong);
        unsafe fn idalib_make_name_non_weak(ea: c_ulonglong);
        unsafe fn idalib_dummy_name_ea(name: *const c_char) -> c_ulonglong;
        unsafe fn idalib_set_dummy_name(from: c_ulonglong, ea: c_ulonglong) -> bool;
        unsafe fn idalib_make_name_auto(ea: c_ulonglong) -> bool;
        unsafe fn idalib_make_name_user(ea: c_ulonglong) -> bool;
        unsafe fn idalib_hide_name(ea: c_ulonglong);
        unsafe fn idalib_show_name(ea: c_ulonglong);
        unsafe fn idalib_rebuild_nlist();
        unsafe fn idalib_cleanup_name(ea: c_ulonglong, name: *const c_char, flags: u32) -> String;

        // auto-analysis
        unsafe fn idalib_get_auto_state() -> c_int;
        unsafe fn idalib_set_auto_state(new_state: c_int) -> c_int;
        unsafe fn idalib_set_ida_state(st: c_int) -> c_int;
        unsafe fn idalib_auto_mark(ea: c_ulonglong, atype: c_int);
        unsafe fn idalib_auto_mark_range(start: c_ulonglong, end: c_ulonglong, atype: c_int);
        unsafe fn idalib_auto_unmark(start: c_ulonglong, end: c_ulonglong, atype: c_int);
        unsafe fn idalib_plan_ea(ea: c_ulonglong);
        unsafe fn idalib_plan_range(sEA: c_ulonglong, eEA: c_ulonglong);
        unsafe fn idalib_auto_make_code(ea: c_ulonglong);
        unsafe fn idalib_auto_make_proc(ea: c_ulonglong);
        unsafe fn idalib_auto_is_ok() -> bool;
        unsafe fn idalib_auto_cancel(ea1: c_ulonglong, ea2: c_ulonglong);
        unsafe fn idalib_plan_and_wait(
            ea1: c_ulonglong,
            ea2: c_ulonglong,
            final_pass: bool,
        ) -> c_int;
        unsafe fn idalib_auto_wait_range(ea1: c_ulonglong, ea2: c_ulonglong) -> i64;
        unsafe fn idalib_auto_make_step(ea1: c_ulonglong, ea2: c_ulonglong) -> bool;
        unsafe fn idalib_peek_auto_queue(low_ea: c_ulonglong, atype: c_int) -> c_ulonglong;
        unsafe fn idalib_is_auto_enabled() -> bool;
        unsafe fn idalib_enable_auto(enable: bool) -> bool;
        unsafe fn idalib_reanalyze_callers(ea: c_ulonglong, noret: bool);
        unsafe fn idalib_revert_ida_decisions(ea1: c_ulonglong, ea2: c_ulonglong);
        unsafe fn idalib_auto_apply_type(caller: c_ulonglong, callee: c_ulonglong);
        unsafe fn idalib_auto_recreate_insn(ea: c_ulonglong) -> c_int;
        unsafe fn idalib_may_trace_sp() -> bool;
        unsafe fn idalib_may_create_stkvars() -> bool;

        // frame/stack
        unsafe fn idalib_add_frame(
            pfn: *mut func_t,
            frsize: i64,
            frregs: u16,
            argsize: u64,
        ) -> bool;
        unsafe fn idalib_del_frame(pfn: *mut func_t) -> bool;
        unsafe fn idalib_set_frame_size(
            pfn: *mut func_t,
            frsize: u64,
            frregs: u16,
            argsize: u64,
        ) -> bool;
        unsafe fn idalib_get_frame_size(pfn: *const func_t) -> u64;
        unsafe fn idalib_get_frame_retsize(pfn: *const func_t) -> c_int;
        unsafe fn idalib_frame_off_args(pfn: *const func_t) -> c_ulonglong;
        unsafe fn idalib_frame_off_retaddr(pfn: *const func_t) -> c_ulonglong;
        unsafe fn idalib_frame_off_savregs(pfn: *const func_t) -> c_ulonglong;
        unsafe fn idalib_frame_off_lvars(pfn: *const func_t) -> c_ulonglong;
        unsafe fn idalib_get_frame_part_args(
            pfn: *const func_t,
            start: *mut c_ulonglong,
            end: *mut c_ulonglong,
        );
        unsafe fn idalib_get_frame_part_retaddr(
            pfn: *const func_t,
            start: *mut c_ulonglong,
            end: *mut c_ulonglong,
        );
        unsafe fn idalib_get_frame_part_savregs(
            pfn: *const func_t,
            start: *mut c_ulonglong,
            end: *mut c_ulonglong,
        );
        unsafe fn idalib_get_frame_part_lvars(
            pfn: *const func_t,
            start: *mut c_ulonglong,
            end: *mut c_ulonglong,
        );
        unsafe fn idalib_update_fpd(pfn: *mut func_t, fpd: u64) -> bool;
        unsafe fn idalib_set_purged(
            ea: c_ulonglong,
            nbytes: c_int,
            override_old_value: bool,
        ) -> bool;
        unsafe fn idalib_add_auto_stkpnt(pfn: *mut func_t, ea: c_ulonglong, delta: i64) -> bool;
        unsafe fn idalib_add_user_stkpnt(ea: c_ulonglong, delta: i64) -> bool;
        unsafe fn idalib_del_stkpnt(pfn: *mut func_t, ea: c_ulonglong) -> bool;
        unsafe fn idalib_get_spd(pfn: *mut func_t, ea: c_ulonglong) -> i64;
        unsafe fn idalib_get_effective_spd(pfn: *mut func_t, ea: c_ulonglong) -> i64;
        unsafe fn idalib_get_sp_delta(pfn: *mut func_t, ea: c_ulonglong) -> i64;
        unsafe fn idalib_set_auto_spd(pfn: *mut func_t, ea: c_ulonglong, new_spd: i64) -> bool;
        unsafe fn idalib_build_stkvar_name(pfn: *const func_t, v: i64) -> String;
        unsafe fn idalib_has_regvar(pfn: *mut func_t, ea: c_ulonglong) -> bool;
        unsafe fn idalib_add_regvar(
            pfn: *mut func_t,
            ea1: c_ulonglong,
            ea2: c_ulonglong,
            canon: *const c_char,
            user: *const c_char,
            cmt: *const c_char,
        ) -> c_int;
        unsafe fn idalib_del_regvar(
            pfn: *mut func_t,
            ea1: c_ulonglong,
            ea2: c_ulonglong,
            canon: *const c_char,
        ) -> c_int;
        unsafe fn idalib_func_frsize(pfn: *const func_t) -> i64;
        unsafe fn idalib_func_frregs(pfn: *const func_t) -> u16;
        unsafe fn idalib_func_fpd(pfn: *const func_t) -> i64;
        unsafe fn idalib_func_argsize(pfn: *const func_t) -> u64;

        // fixup operations
        unsafe fn idalib_exists_fixup(source: c_ulonglong) -> bool;
        unsafe fn idalib_get_fixup(
            source: c_ulonglong,
            fixup_type: *mut u16,
            flags: *mut u32,
            sel: *mut c_ulonglong,
            off: *mut c_ulonglong,
            displacement: *mut i64,
        ) -> bool;
        unsafe fn idalib_set_fixup(
            source: c_ulonglong,
            fixup_type: u16,
            flags: u32,
            sel: c_ulonglong,
            off: c_ulonglong,
            displacement: i64,
        );
        unsafe fn idalib_del_fixup(source: c_ulonglong);
        unsafe fn idalib_get_first_fixup_ea() -> c_ulonglong;
        unsafe fn idalib_get_next_fixup_ea(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_prev_fixup_ea(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_contains_fixups(ea: c_ulonglong, size: u64) -> bool;
        unsafe fn idalib_apply_fixup(
            item_ea: c_ulonglong,
            fixup_ea: c_ulonglong,
            n: c_int,
            is_macro: bool,
        ) -> bool;
        unsafe fn idalib_get_fixup_value(ea: c_ulonglong, fixup_type: u16) -> u64;
        unsafe fn idalib_calc_fixup_size(fixup_type: u16) -> c_int;
        unsafe fn idalib_get_fixup_desc(source: c_ulonglong) -> String;
        unsafe fn idalib_is_fixup_custom(fixup_type: u16) -> bool;

        // lines/disassembly
        unsafe fn idalib_generate_disasm_line(ea: c_ulonglong, flags: c_int) -> String;
        unsafe fn idalib_generate_disasm_line_no_tags(ea: c_ulonglong) -> String;
        unsafe fn idalib_generate_disassembly(
            ea: c_ulonglong,
            maxlines: c_int,
            out: &mut Vec<String>,
        ) -> c_int;
        unsafe fn idalib_tag_remove(line: *const c_char) -> String;
        unsafe fn idalib_tag_strlen(line: *const c_char) -> i64;
        unsafe fn idalib_add_extra_line(ea: c_ulonglong, isprev: bool, line: *const c_char)
        -> bool;
        unsafe fn idalib_add_extra_cmt(ea: c_ulonglong, isprev: bool, cmt: *const c_char) -> bool;
        unsafe fn idalib_add_pgm_cmt(cmt: *const c_char) -> bool;
        unsafe fn idalib_get_extra_cmt(ea: c_ulonglong, n: c_int) -> String;
        unsafe fn idalib_del_extra_cmt(ea: c_ulonglong, n: c_int) -> bool;
        unsafe fn idalib_delete_extra_cmts(ea: c_ulonglong, n: c_int);
        unsafe fn idalib_add_sourcefile(
            ea1: c_ulonglong,
            ea2: c_ulonglong,
            filename: *const c_char,
        ) -> bool;
        unsafe fn idalib_get_sourcefile(ea: c_ulonglong) -> String;
        unsafe fn idalib_del_sourcefile(ea: c_ulonglong) -> bool;
        unsafe fn idalib_calc_prefix_color(ea: c_ulonglong) -> u8;
        unsafe fn idalib_calc_bg_color(ea: c_ulonglong) -> u32;

        // xref operations
        unsafe fn idalib_add_cref(from: c_ulonglong, to: c_ulonglong, xref_type: c_int) -> bool;
        unsafe fn idalib_del_cref(from: c_ulonglong, to: c_ulonglong, expand: bool) -> bool;
        unsafe fn idalib_add_dref(from: c_ulonglong, to: c_ulonglong, xref_type: c_int) -> bool;
        unsafe fn idalib_del_dref(from: c_ulonglong, to: c_ulonglong);
        unsafe fn idalib_xrefchar(xrtype: c_int) -> c_char;
        unsafe fn idalib_has_jump_or_flow_xref(ea: c_ulonglong) -> bool;
        unsafe fn idalib_create_xrefs_from(ea: c_ulonglong) -> bool;
        unsafe fn idalib_delete_all_xrefs_from(ea: c_ulonglong, expand: bool);
        unsafe fn idalib_get_first_dref_from(from: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_next_dref_from(from: c_ulonglong, current: c_ulonglong)
        -> c_ulonglong;
        unsafe fn idalib_get_first_dref_to(to: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_next_dref_to(to: c_ulonglong, current: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_first_cref_from(from: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_next_cref_from(from: c_ulonglong, current: c_ulonglong)
        -> c_ulonglong;
        unsafe fn idalib_get_first_cref_to(to: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_next_cref_to(to: c_ulonglong, current: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_first_fcref_from(from: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_next_fcref_from(
            from: c_ulonglong,
            current: c_ulonglong,
        ) -> c_ulonglong;
        unsafe fn idalib_get_first_fcref_to(to: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_next_fcref_to(to: c_ulonglong, current: c_ulonglong) -> c_ulonglong;

        // function manipulation
        unsafe fn idalib_add_func(ea1: c_ulonglong, ea2: c_ulonglong) -> bool;
        unsafe fn idalib_del_func(ea: c_ulonglong) -> bool;
        unsafe fn idalib_set_func_start(ea: c_ulonglong, newstart: c_ulonglong) -> c_int;
        unsafe fn idalib_set_func_end(ea: c_ulonglong, newend: c_ulonglong) -> bool;
        unsafe fn idalib_update_func(pfn: *mut func_t) -> bool;
        unsafe fn idalib_get_prev_func(ea: c_ulonglong) -> *mut func_t;
        unsafe fn idalib_get_next_func(ea: c_ulonglong) -> *mut func_t;
        unsafe fn idalib_reanalyze_function(
            pfn: *mut func_t,
            ea1: c_ulonglong,
            ea2: c_ulonglong,
            analyze_parents: bool,
        );
        unsafe fn idalib_find_func_bounds(nfn: *mut func_t, flags: c_int) -> c_int;
        unsafe fn idalib_calc_func_size(pfn: *mut func_t) -> u64;
        unsafe fn idalib_get_func_bitness(pfn: *const func_t) -> c_int;
        unsafe fn idalib_set_visible_func(pfn: *mut func_t, visible: bool);
        unsafe fn idalib_is_visible_func(pfn: *mut func_t) -> bool;
        unsafe fn idalib_func_does_return(callee: c_ulonglong) -> bool;
        unsafe fn idalib_reanalyze_noret_flag(ea: c_ulonglong) -> bool;
        unsafe fn idalib_set_noret_insn(insn_ea: c_ulonglong, noret: bool) -> bool;
        unsafe fn idalib_is_func_locked(pfn: *const func_t) -> bool;
        unsafe fn idalib_lock_func_range(pfn: *const func_t, lock: bool);
        unsafe fn idalib_append_func_tail(
            pfn: *mut func_t,
            ea1: c_ulonglong,
            ea2: c_ulonglong,
        ) -> bool;
        unsafe fn idalib_remove_func_tail(pfn: *mut func_t, tail_ea: c_ulonglong) -> bool;
        unsafe fn idalib_set_tail_owner(fnt: *mut func_t, new_owner: c_ulonglong) -> bool;
        unsafe fn idalib_get_fchunk(ea: c_ulonglong) -> *mut func_t;
        unsafe fn idalib_getn_fchunk(n: c_int) -> *mut func_t;
        unsafe fn idalib_get_fchunk_qty() -> usize;
        unsafe fn idalib_get_prev_func_addr(pfn: *mut func_t, ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_next_func_addr(pfn: *mut func_t, ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_func_ranges(pfn: *mut func_t) -> String;
        unsafe fn idalib_apply_idasgn_to(
            signame: *const c_char,
            ea: c_ulonglong,
            is_startup: bool,
        ) -> c_int;
        unsafe fn idalib_get_idasgn_qty() -> c_int;
        unsafe fn idalib_plan_to_apply_idasgn(fname: *const c_char) -> c_int;

        // segment manipulation
        unsafe fn idalib_add_segm(
            para: c_ulonglong,
            start: c_ulonglong,
            end: c_ulonglong,
            name: *const c_char,
            sclass: *const c_char,
        ) -> bool;
        unsafe fn idalib_del_segm(ea: c_ulonglong, flags: c_int) -> bool;
        unsafe fn idalib_set_segm_start(
            ea: c_ulonglong,
            newstart: c_ulonglong,
            flags: c_int,
        ) -> bool;
        unsafe fn idalib_set_segm_end(ea: c_ulonglong, newend: c_ulonglong, flags: c_int) -> bool;
        unsafe fn idalib_move_segm_start(
            ea: c_ulonglong,
            newstart: c_ulonglong,
            mode: c_int,
        ) -> bool;
        unsafe fn idalib_set_segm_base(s: *mut segment_t, newbase: c_ulonglong) -> bool;
        unsafe fn idalib_get_segm_num(ea: c_ulonglong) -> c_int;
        unsafe fn idalib_get_next_seg(ea: c_ulonglong) -> *mut segment_t;
        unsafe fn idalib_get_prev_seg(ea: c_ulonglong) -> *mut segment_t;
        unsafe fn idalib_get_first_seg() -> *mut segment_t;
        unsafe fn idalib_get_last_seg() -> *mut segment_t;
        unsafe fn idalib_set_visible_segm(s: *mut segment_t, visible: bool);
        unsafe fn idalib_is_visible_segm(s: *mut segment_t) -> bool;
        unsafe fn idalib_is_spec_segm(seg_type: u8) -> bool;
        unsafe fn idalib_is_spec_ea(ea: c_ulonglong) -> bool;
        unsafe fn idalib_lock_segm(segm: *const segment_t, lock: bool);
        unsafe fn idalib_is_segm_locked(segm: *const segment_t) -> bool;
        unsafe fn idalib_move_segm(s: *mut segment_t, to: c_ulonglong, flags: c_int) -> c_int;
        unsafe fn idalib_rebase_program(delta: i64, flags: c_int) -> c_int;
        unsafe fn idalib_get_segm_class(s: *const segment_t) -> String;
        unsafe fn idalib_set_segm_class(s: *mut segment_t, sclass: *const c_char) -> c_int;
        unsafe fn idalib_change_segment_status(s: *mut segment_t, is_deb_segm: bool) -> c_int;
        unsafe fn idalib_take_memory_snapshot(snapshot_type: c_int) -> bool;
        unsafe fn idalib_is_miniidb() -> bool;
        unsafe fn idalib_setup_selector(segbase: c_ulonglong) -> u64;
        unsafe fn idalib_allocate_selector(segbase: c_ulonglong) -> u64;
        unsafe fn idalib_find_free_selector() -> u64;
        unsafe fn idalib_del_selector(selector: u64);
        unsafe fn idalib_get_selector_qty() -> usize;
        unsafe fn idalib_sel2para(selector: u64) -> c_ulonglong;
        unsafe fn idalib_find_selector(base: c_ulonglong) -> u64;

        // problem markers
        unsafe fn idalib_remember_problem(prob_type: c_int, ea: c_ulonglong, msg: *const c_char);
        unsafe fn idalib_get_problem(prob_type: c_int, lowea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_forget_problem(prob_type: c_int, ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_problem_present(prob_type: c_int, ea: c_ulonglong) -> bool;
        unsafe fn idalib_get_problem_name(prob_type: c_int, longname: bool) -> String;
        unsafe fn idalib_get_problem_desc(prob_type: c_int, ea: c_ulonglong) -> String;

        // offset operations
        unsafe fn idalib_get_default_reftype(ea: c_ulonglong) -> c_int;
        unsafe fn idalib_op_offset(
            ea: c_ulonglong,
            n: c_int,
            reftype: c_int,
            target: c_ulonglong,
            base: c_ulonglong,
            tdelta: i64,
        ) -> bool;
        unsafe fn idalib_get_offset_expression(
            ea: c_ulonglong,
            n: c_int,
            from: c_ulonglong,
            offset: i64,
            geteflag: c_int,
        ) -> String;
        unsafe fn idalib_can_be_off32(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_calc_offset_base(ea: c_ulonglong, n: c_int) -> c_ulonglong;
        unsafe fn idalib_calc_probable_base_by_value(ea: c_ulonglong, off: u64) -> c_ulonglong;
        unsafe fn idalib_set_refinfo(
            ea: c_ulonglong,
            n: c_int,
            reftype: c_int,
            target: c_ulonglong,
            base: c_ulonglong,
            tdelta: i64,
        ) -> bool;
        unsafe fn idalib_get_refinfo(
            ea: c_ulonglong,
            n: c_int,
            reftype: *mut c_int,
            target: *mut c_ulonglong,
            base: *mut c_ulonglong,
            tdelta: *mut i64,
        ) -> bool;
        unsafe fn idalib_del_refinfo(ea: c_ulonglong, n: c_int) -> bool;

        // extended nalt operations
        unsafe fn idalib_get_root_filename() -> String;
        unsafe fn idalib_dbg_get_input_path() -> String;
        unsafe fn idalib_get_str_type(ea: c_ulonglong) -> u32;
        unsafe fn idalib_set_str_type(ea: c_ulonglong, strtype: u32);
        unsafe fn idalib_del_str_type(ea: c_ulonglong);
        unsafe fn idalib_get_item_color(ea: c_ulonglong) -> u32;
        unsafe fn idalib_set_item_color(ea: c_ulonglong, color: u32);
        unsafe fn idalib_del_item_color(ea: c_ulonglong) -> bool;
        unsafe fn idalib_get_source_linnum(ea: c_ulonglong) -> u64;
        unsafe fn idalib_set_source_linnum(ea: c_ulonglong, lnnum: u64);
        unsafe fn idalib_del_source_linnum(ea: c_ulonglong);
        unsafe fn idalib_get_aflags(ea: c_ulonglong) -> u32;
        unsafe fn idalib_set_aflags(ea: c_ulonglong, flags: u32);
        unsafe fn idalib_set_abits(ea: c_ulonglong, bits: u32);
        unsafe fn idalib_clr_abits(ea: c_ulonglong, bits: u32);
        unsafe fn idalib_del_aflags(ea: c_ulonglong);
        unsafe fn idalib_get_import_module_qty() -> u32;
        unsafe fn idalib_get_import_module_name(mod_index: c_int) -> String;
        unsafe fn idalib_get_encoding_qty() -> c_int;
        unsafe fn idalib_get_encoding_name(idx: c_int) -> String;
        unsafe fn idalib_add_encoding(encname: *const c_char) -> c_int;
        unsafe fn idalib_del_encoding(idx: c_int) -> bool;
        unsafe fn idalib_get_encoding_bpu(idx: c_int) -> c_int;
        unsafe fn idalib_has_switch_info(ea: c_ulonglong) -> bool;
        unsafe fn idalib_get_switch_jumps(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_get_switch_ncases(ea: c_ulonglong) -> c_int;
        unsafe fn idalib_get_switch_lowcase(ea: c_ulonglong) -> i64;
        unsafe fn idalib_del_switch_info(ea: c_ulonglong);
        unsafe fn idalib_has_tinfo(ea: c_ulonglong) -> bool;
        unsafe fn idalib_del_tinfo(ea: c_ulonglong) -> bool;
        unsafe fn idalib_has_op_tinfo(ea: c_ulonglong, n: c_int) -> bool;

        // segment register operations
        unsafe fn idalib_get_sreg(ea: c_ulonglong, rg: c_int) -> u64;
        unsafe fn idalib_set_default_sreg_value(sg: *mut segment_t, rg: c_int, value: u64) -> bool;
        unsafe fn idalib_set_sreg_at_next_code(
            ea1: c_ulonglong,
            ea2: c_ulonglong,
            rg: c_int,
            value: u64,
        );
        unsafe fn idalib_split_sreg_range(
            ea: c_ulonglong,
            rg: c_int,
            value: u64,
            tag: c_int,
            silent: bool,
        ) -> bool;
        unsafe fn idalib_get_sreg_range(
            ea: c_ulonglong,
            rg: c_int,
            start: *mut c_ulonglong,
            end: *mut c_ulonglong,
            val: *mut u64,
            tag: *mut c_int,
        ) -> bool;
        unsafe fn idalib_get_prev_sreg_range(
            ea: c_ulonglong,
            rg: c_int,
            start: *mut c_ulonglong,
            end: *mut c_ulonglong,
            val: *mut u64,
            tag: *mut c_int,
        ) -> bool;
        unsafe fn idalib_set_default_dataseg(ds_sel: u64);
        unsafe fn idalib_get_sreg_ranges_qty(rg: c_int) -> usize;
        unsafe fn idalib_del_sreg_range(ea: c_ulonglong, rg: c_int) -> bool;

        // try/catch block operations
        unsafe fn idalib_find_syseh(ea: c_ulonglong) -> c_ulonglong;
        unsafe fn idalib_is_ea_tryblks(ea: c_ulonglong, flags: u32) -> bool;
        unsafe fn idalib_del_tryblks(start: c_ulonglong, end: c_ulonglong);
        unsafe fn idalib_get_tryblks_qty(start: c_ulonglong, end: c_ulonglong) -> usize;

        // type information operations
        unsafe fn idalib_get_type_str(ea: c_ulonglong) -> String;
        unsafe fn idalib_set_type_str(ea: c_ulonglong, type_str: *const c_char) -> bool;
        unsafe fn idalib_del_tinfo_at(ea: c_ulonglong) -> bool;
        unsafe fn idalib_get_op_type_str(ea: c_ulonglong, n: c_int) -> String;
        unsafe fn idalib_set_op_type_str(
            ea: c_ulonglong,
            n: c_int,
            type_str: *const c_char,
        ) -> bool;
        unsafe fn idalib_get_func_type_str(ea: c_ulonglong) -> String;
        unsafe fn idalib_set_func_type_str(ea: c_ulonglong, type_str: *const c_char) -> bool;
        unsafe fn idalib_get_named_type_str(name: *const c_char) -> String;
        unsafe fn idalib_named_type_exists(name: *const c_char) -> bool;
        unsafe fn idalib_get_named_type_ordinal(name: *const c_char) -> u32;
        unsafe fn idalib_get_numbered_type_str(ordinal: u32) -> String;
        unsafe fn idalib_get_ordinal_qty() -> u32;
        unsafe fn idalib_is_type_struct(ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_type_union(ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_type_enum(ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_type_ptr(ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_type_array(ea: c_ulonglong) -> bool;
        unsafe fn idalib_is_type_func(ea: c_ulonglong) -> bool;
        unsafe fn idalib_get_type_size(ea: c_ulonglong) -> u64;
        unsafe fn idalib_get_named_type_size(name: *const c_char) -> u64;
        unsafe fn idalib_parse_decl(
            decl: *const c_char,
            out_name: *mut String,
            out_type: *mut String,
        ) -> bool;
        unsafe fn idalib_get_compiler_id() -> u8;
        unsafe fn idalib_get_compiler_name_str() -> String;
        unsafe fn idalib_get_compiler_abbr_str() -> String;
        unsafe fn idalib_get_abi_name_str() -> String;
        unsafe fn idalib_print_type(ea: c_ulonglong, prtype_flags: c_int) -> String;
        unsafe fn idalib_get_udt_member_count(type_name: *const c_char) -> c_int;
        unsafe fn idalib_get_udt_member_name(type_name: *const c_char, idx: c_int) -> String;
        unsafe fn idalib_get_udt_member_type(type_name: *const c_char, idx: c_int) -> String;
        unsafe fn idalib_get_udt_member_offset(type_name: *const c_char, idx: c_int) -> i64;
        unsafe fn idalib_get_enum_member_count(type_name: *const c_char) -> c_int;
        unsafe fn idalib_get_enum_member_name(type_name: *const c_char, idx: c_int) -> String;
        unsafe fn idalib_get_enum_member_value(type_name: *const c_char, idx: c_int) -> i64;
        unsafe fn idalib_get_func_arg_count(ea: c_ulonglong) -> c_int;
        unsafe fn idalib_get_func_arg_name(ea: c_ulonglong, idx: c_int) -> String;
        unsafe fn idalib_get_func_arg_type(ea: c_ulonglong, idx: c_int) -> String;
        unsafe fn idalib_get_func_rettype(ea: c_ulonglong) -> String;
        unsafe fn idalib_get_func_cc(ea: c_ulonglong) -> c_int;
        unsafe fn idalib_add_local_type(decl: *const c_char, name: *const c_char) -> u32;
        unsafe fn idalib_del_local_type(name: *const c_char) -> bool;
        unsafe fn idalib_add_til(tilname: *const c_char) -> c_int;
        unsafe fn idalib_del_til(tilname: *const c_char) -> bool;

        // netnode operations
        unsafe fn idalib_ea2node(ea: c_ulonglong) -> u64;
        unsafe fn idalib_node2ea(ndx: u64) -> c_ulonglong;
        unsafe fn idalib_netnode_create(name: *const c_char) -> u64;
        unsafe fn idalib_netnode_find(name: *const c_char) -> u64;
        unsafe fn idalib_netnode_kill(nodeidx: u64);
        unsafe fn idalib_netnode_get_name(nodeidx: u64) -> String;
        unsafe fn idalib_netnode_rename(nodeidx: u64, newname: *const c_char) -> bool;
        unsafe fn idalib_netnode_altval(nodeidx: u64, alt: u64, tag: c_int) -> u64;
        unsafe fn idalib_netnode_altset(nodeidx: u64, alt: u64, value: u64, tag: c_int) -> bool;
        unsafe fn idalib_netnode_altdel(nodeidx: u64, alt: u64, tag: c_int) -> bool;
        unsafe fn idalib_netnode_supval(nodeidx: u64, alt: u64, tag: c_int) -> Vec<u8>;
        unsafe fn idalib_netnode_supset(
            nodeidx: u64,
            alt: u64,
            data: *const u8,
            len: usize,
            tag: c_int,
        ) -> bool;
        unsafe fn idalib_netnode_supdel(nodeidx: u64, alt: u64, tag: c_int) -> bool;
        unsafe fn idalib_netnode_supstr(nodeidx: u64, alt: u64, tag: c_int) -> String;
        unsafe fn idalib_netnode_supfirst(nodeidx: u64, tag: c_int) -> u64;
        unsafe fn idalib_netnode_supnext(nodeidx: u64, cur: u64, tag: c_int) -> u64;
        unsafe fn idalib_netnode_suplast(nodeidx: u64, tag: c_int) -> u64;
        unsafe fn idalib_netnode_supprev(nodeidx: u64, cur: u64, tag: c_int) -> u64;
        unsafe fn idalib_netnode_supdel_all(nodeidx: u64, tag: c_int) -> bool;
        unsafe fn idalib_netnode_hashval_long(nodeidx: u64, idx: *const c_char, tag: c_int) -> u64;
        unsafe fn idalib_netnode_hashset(
            nodeidx: u64,
            idx: *const c_char,
            data: *const u8,
            len: usize,
            tag: c_int,
        ) -> bool;
        unsafe fn idalib_netnode_hashset_long(
            nodeidx: u64,
            idx: *const c_char,
            value: u64,
            tag: c_int,
        ) -> bool;
        unsafe fn idalib_netnode_hashdel(nodeidx: u64, idx: *const c_char, tag: c_int) -> bool;
        unsafe fn idalib_netnode_hashstr(nodeidx: u64, idx: *const c_char, tag: c_int) -> String;
        unsafe fn idalib_netnode_hashfirst(nodeidx: u64, tag: c_int) -> String;
        unsafe fn idalib_netnode_hashnext(nodeidx: u64, idx: *const c_char, tag: c_int) -> String;
        unsafe fn idalib_netnode_blobsize(nodeidx: u64, start: u64, tag: c_int) -> usize;
        unsafe fn idalib_netnode_setblob(
            nodeidx: u64,
            buf: *const u8,
            size: usize,
            start: u64,
            tag: c_int,
        ) -> bool;
        unsafe fn idalib_netnode_delblob(nodeidx: u64, start: u64, tag: c_int) -> c_int;
        unsafe fn idalib_netnode_valstr(nodeidx: u64) -> String;
        unsafe fn idalib_netnode_set_value(nodeidx: u64, value: *const u8, length: usize) -> bool;
        unsafe fn idalib_netnode_delvalue(nodeidx: u64) -> bool;
        unsafe fn idalib_netnode_inited() -> bool;
    }
}

pub use ffi::{ea_t, range_t};
pub const BADADDR: ea_t = into_ea(0xffffffff_ffffffffu64);

#[inline(always)]
pub const fn into_ea(v: u64) -> ea_t {
    c_ulonglong(v)
}

#[inline(always)]
pub const fn from_ea(v: ea_t) -> u64 {
    v.0
}

pub mod entry {
    pub use super::ffi::{get_entry, get_entry_ordinal, get_entry_qty, uval_t};
    pub use super::ffix::idalib_entry_name;
}

pub mod insn {
    use std::mem::MaybeUninit;

    use super::ea_t;
    use super::ffi::decode_insn;

    pub use super::pod::insn_t;

    pub fn decode(ea: ea_t) -> Option<insn_t> {
        let mut insn = MaybeUninit::<insn_t>::zeroed();
        unsafe { (decode_insn(insn.as_mut_ptr(), ea).0 > 0).then(|| insn.assume_init()) }
    }

    pub mod op {
        pub use super::super::ffi::{
            IRI_EXTENDED, IRI_RET_LITERALLY, IRI_SKIP_RETTARGET, IRI_STRICT, dt_bitfild, dt_byte,
            dt_byte16, dt_byte32, dt_byte64, dt_code, dt_double, dt_dword, dt_float, dt_fword,
            dt_half, dt_ldbl, dt_packreal, dt_qword, dt_string, dt_tbyte, dt_unicode, dt_void,
            dt_word, o_displ, o_far, o_idpspec0, o_idpspec1, o_idpspec2, o_idpspec3, o_idpspec4,
            o_idpspec5, o_imm, o_mem, o_near, o_phrase, o_reg, o_void,
        };
        pub use super::super::pod::{
            OF_NO_BASE_DISP, OF_NUMBER, OF_OUTER_DISP, OF_SHOW, op_dtype_t, op_t, optype_t,
        };
    }

    pub mod arm {
        #![allow(non_camel_case_types)]
        #![allow(non_upper_case_globals)]
        #![allow(unused)]

        include!(concat!(env!("OUT_DIR"), "/insn_arm.rs"));
    }

    pub mod mips {
        #![allow(non_camel_case_types)]
        #![allow(non_upper_case_globals)]
        #![allow(unused)]

        include!(concat!(env!("OUT_DIR"), "/insn_mips.rs"));
    }

    pub mod x86 {
        #![allow(non_camel_case_types)]
        #![allow(non_upper_case_globals)]
        #![allow(unused)]

        include!(concat!(env!("OUT_DIR"), "/insn_x86.rs"));
    }
}

pub mod func {
    pub use super::ffi::{
        calc_thunk_func_target, fc_block_type_t, func_t, gdl_graph_t, get_func, get_func_num,
        get_func_qty, getn_func, lock_func, qbasic_block_t, qflow_chart_t,
    };
    pub use super::ffix::{
        // Function manipulation
        idalib_add_func,
        idalib_append_func_tail,
        idalib_apply_idasgn_to,
        idalib_calc_func_size,
        idalib_del_func,
        idalib_find_func_bounds,
        idalib_func_does_return,
        idalib_func_flags,
        idalib_func_flow_chart,
        idalib_func_name,
        idalib_get_fchunk,
        idalib_get_fchunk_qty,
        idalib_get_func_bitness,
        idalib_get_func_cmt,
        idalib_get_func_ranges,
        idalib_get_idasgn_qty,
        idalib_get_next_func,
        idalib_get_next_func_addr,
        idalib_get_prev_func,
        idalib_get_prev_func_addr,
        idalib_getn_fchunk,
        idalib_is_func_locked,
        idalib_is_visible_func,
        idalib_lock_func_range,
        idalib_plan_to_apply_idasgn,
        idalib_qbasic_block_preds,
        idalib_qbasic_block_succs,
        idalib_qflow_graph_getn_block,
        idalib_reanalyze_function,
        idalib_reanalyze_noret_flag,
        idalib_remove_func_tail,
        idalib_set_func_cmt,
        idalib_set_func_end,
        idalib_set_func_start,
        idalib_set_noret_insn,
        idalib_set_tail_owner,
        idalib_set_visible_func,
        idalib_update_func,
    };

    pub mod flags {
        pub use super::super::ffi::{
            FUNC_BOTTOMBP, FUNC_FAR, FUNC_FRAME, FUNC_FUZZY_SP, FUNC_HIDDEN, FUNC_LIB, FUNC_LUMINA,
            FUNC_NORET, FUNC_NORET_PENDING, FUNC_OUTLINE, FUNC_PROLOG_OK, FUNC_PURGED_OK,
            FUNC_REANALYZE, FUNC_RESERVED, FUNC_SP_READY, FUNC_STATICDEF, FUNC_TAIL, FUNC_THUNK,
            FUNC_USERFAR,
        };
    }

    pub mod cfg_flags {
        pub use super::super::ffi::{
            FC_APPND, FC_CALL_ENDS, FC_CHKBREAK, FC_NOEXT, FC_NOPREDS, FC_OUTLINES, FC_PRINT,
            FC_RESERVED,
        };
    }

    /// Function bounds flags
    pub mod bounds_flags {
        pub const FIND_FUNC_DEFINE: i32 = 0x0001;
        pub const FIND_FUNC_IGNOREFN: i32 = 0x0002;
        pub const FIND_FUNC_KEEPBD: i32 = 0x0004;
    }
}

pub mod processor {
    pub use super::ffi::{get_ph, processor_t};
    pub use super::ffix::{
        idalib_is_thumb_at, idalib_ph_id, idalib_ph_long_name, idalib_ph_short_name,
    };

    pub use super::idp as ids;
}

pub mod segment {
    pub use super::ffi::{
        SEG_ABSSYM, SEG_BSS, SEG_CODE, SEG_COMM, SEG_DATA, SEG_GRP, SEG_IMEM, SEG_IMP,
        SEG_MAX_SEGTYPE_CODE, SEG_NORM, SEG_NULL, SEG_UNDF, SEG_XTRN, SEGPERM_EXEC, SEGPERM_MAXVAL,
        SEGPERM_READ, SEGPERM_WRITE, get_segm_by_name, get_segm_qty, getnseg, getseg, lock_segment,
        saAbs, saGroup, saRel_MAX_ALIGN_CODE, saRel4K, saRel32Bytes, saRel64Bytes, saRel128Bytes,
        saRel512Bytes, saRel1024Bytes, saRel2048Bytes, saRelByte, saRelDble, saRelPage, saRelPara,
        saRelQword, saRelWord, segment_t,
    };

    pub use super::ffix::{
        // Segment manipulation
        idalib_add_segm,
        idalib_allocate_selector,
        idalib_change_segment_status,
        idalib_del_segm,
        idalib_del_selector,
        idalib_find_free_selector,
        idalib_find_selector,
        idalib_get_first_seg,
        idalib_get_last_seg,
        idalib_get_next_seg,
        idalib_get_prev_seg,
        idalib_get_segm_class,
        idalib_get_segm_num,
        idalib_get_selector_qty,
        idalib_is_miniidb,
        idalib_is_segm_locked,
        idalib_is_spec_ea,
        idalib_is_spec_segm,
        idalib_is_visible_segm,
        idalib_lock_segm,
        idalib_move_segm,
        idalib_move_segm_start,
        idalib_rebase_program,
        idalib_segm_align,
        idalib_segm_bitness,
        idalib_segm_bytes,
        idalib_segm_name,
        idalib_segm_perm,
        idalib_segm_type,
        idalib_sel2para,
        idalib_set_segm_base,
        idalib_set_segm_class,
        idalib_set_segm_end,
        idalib_set_segm_start,
        idalib_set_visible_segm,
        // Selector operations
        idalib_setup_selector,
        idalib_take_memory_snapshot,
    };

    /// Segment deletion flags
    pub mod del_flags {
        pub const SEGMOD_KILL: i32 = 0x0001;
        pub const SEGMOD_KEEP: i32 = 0x0002;
        pub const SEGMOD_SILENT: i32 = 0x0004;
        pub const SEGMOD_KEEP0: i32 = 0x0008;
        pub const SEGMOD_KEEPSEL: i32 = 0x0010;
        pub const SEGMOD_NOMOVE: i32 = 0x0020;
        pub const SEGMOD_SPARSE: i32 = 0x0040;
    }

    /// Move segment return codes
    pub mod move_codes {
        pub const MSC_OK: i32 = 0;
        pub const MSC_BADARG: i32 = -1;
        pub const MSC_BUSY: i32 = -2;
        pub const MSC_OVERLAP: i32 = -3;
        pub const MSC_NETNODE: i32 = -4;
        pub const MSC_LOADER: i32 = -5;
        pub const MSC_LOCK: i32 = -6;
        pub const MSC_MEMORY: i32 = -7;
    }
}

pub mod bytes {
    pub use super::ffi::{flags64_t, get_flags, is_code, is_data};
    pub use super::ffix::{
        // Create data types
        idalib_create_byte,
        idalib_create_double,
        idalib_create_dword,
        idalib_create_float,
        idalib_create_qword,
        idalib_create_word,
        idalib_del_items,
        // Reading
        idalib_get_byte,
        idalib_get_bytes,
        idalib_get_dword,
        // Item navigation
        idalib_get_item_end,
        idalib_get_item_head,
        idalib_get_item_size,
        // Original values
        idalib_get_original_byte,
        idalib_get_original_dword,
        idalib_get_original_qword,
        idalib_get_original_word,
        idalib_get_qword,
        idalib_get_word,
        // Flags inspection
        idalib_has_value,
        idalib_is_byte,
        idalib_is_double,
        idalib_is_dword,
        idalib_is_float,
        idalib_is_flow,
        idalib_is_head,
        idalib_is_loaded,
        idalib_is_mapped,
        idalib_is_qword,
        idalib_is_tail,
        idalib_is_unknown,
        idalib_is_word,
        idalib_next_addr,
        idalib_next_not_tail,
        idalib_next_that,
        idalib_next_unknown,
        // Patching
        idalib_patch_byte,
        idalib_patch_bytes,
        idalib_patch_dword,
        idalib_patch_qword,
        idalib_patch_word,
        idalib_prev_addr,
        idalib_prev_not_tail,
        idalib_prev_that,
        idalib_prev_unknown,
        // Put (modify database)
        idalib_put_byte,
        idalib_put_bytes,
        idalib_put_dword,
        idalib_put_qword,
        idalib_put_word,
        idalib_revert_byte,
    };
}

pub mod util {
    pub use super::ffi::{
        is_align_insn, is_basic_block_end, is_call_insn, is_indirect_jump_insn, is_ret_insn,
        next_head, prev_head, str2reg,
    };
}

pub mod xref {
    pub use super::ffi::{
        XREF_ALL, XREF_BASE, XREF_DATA, XREF_FAR, XREF_MASK, XREF_PASTEND, XREF_TAIL, XREF_USER,
        cref_t, dref_t, has_external_refs, xrefblk_t, xrefblk_t_first_from, xrefblk_t_first_to,
        xrefblk_t_next_from, xrefblk_t_next_to,
    };
    pub use super::ffix::{
        idalib_add_cref, idalib_add_dref, idalib_create_xrefs_from, idalib_del_cref,
        idalib_del_dref, idalib_delete_all_xrefs_from, idalib_get_first_cref_from,
        idalib_get_first_cref_to, idalib_get_first_dref_from, idalib_get_first_dref_to,
        idalib_get_first_fcref_from, idalib_get_first_fcref_to, idalib_get_next_cref_from,
        idalib_get_next_cref_to, idalib_get_next_dref_from, idalib_get_next_dref_to,
        idalib_get_next_fcref_from, idalib_get_next_fcref_to, idalib_has_jump_or_flow_xref,
        idalib_xrefchar,
    };
}

pub mod comments {
    pub use super::ffi::{append_cmt, set_cmt};
    pub use super::ffix::idalib_get_cmt;
}

pub mod conversions {
    pub use super::ffix::idalib_ea2str;
}

pub mod bookmarks {
    pub use super::ffix::{
        idalib_bookmarks_t_erase, idalib_bookmarks_t_find_index, idalib_bookmarks_t_get,
        idalib_bookmarks_t_get_desc, idalib_bookmarks_t_mark, idalib_bookmarks_t_size,
    };
}

pub mod search {
    pub use super::ffix::{idalib_find_defined, idalib_find_imm, idalib_find_text};
}

pub mod strings {
    pub use super::ffi::{build_strlist, clear_strlist, get_strlist_qty};
    pub use super::ffix::{idalib_get_strlist_item_addr, idalib_get_strlist_item_length};
}

pub mod loader {
    pub use super::ffi::{find_plugin, plugin_t, run_plugin};
    pub use super::ffix::{idalib_plugin_flags, idalib_plugin_version};

    pub mod flags {
        pub use super::super::ffi::{
            PLUGIN_DBG, PLUGIN_DRAW, PLUGIN_FIX, PLUGIN_HIDE, PLUGIN_MOD, PLUGIN_MULTI,
            PLUGIN_PROC, PLUGIN_SCRIPTED, PLUGIN_SEG, PLUGIN_UNL,
        };
    }
}

pub mod nalt {
    pub use super::ffi::{
        retrieve_input_file_md5, retrieve_input_file_sha256, retrieve_input_file_size,
    };
    pub use super::ffix::{
        idalib_add_encoding,
        idalib_clr_abits,
        idalib_dbg_get_input_path,
        idalib_del_aflags,
        idalib_del_encoding,
        idalib_del_item_color,
        idalib_del_source_linnum,
        idalib_del_str_type,
        idalib_del_switch_info,
        idalib_del_tinfo,
        // Additional flags
        idalib_get_aflags,
        idalib_get_encoding_bpu,
        idalib_get_encoding_name,
        // Encodings
        idalib_get_encoding_qty,
        idalib_get_import_module_name,
        // Imports
        idalib_get_import_module_qty,
        idalib_get_input_file_path,
        // Item colors
        idalib_get_item_color,
        idalib_get_root_filename,
        // Source line numbers
        idalib_get_source_linnum,
        // String types
        idalib_get_str_type,
        idalib_get_switch_jumps,
        idalib_get_switch_lowcase,
        idalib_get_switch_ncases,
        idalib_has_op_tinfo,
        // Switch info
        idalib_has_switch_info,
        // Type info at address
        idalib_has_tinfo,
        idalib_set_abits,
        idalib_set_aflags,
        idalib_set_item_color,
        idalib_set_source_linnum,
        idalib_set_str_type,
    };

    /// Additional flags (aflags) bits
    pub mod aflags {
        pub const AFL_LINNUM: u32 = 0x00000001;
        pub const AFL_USERSP: u32 = 0x00000002;
        pub const AFL_PUBNAM: u32 = 0x00000004;
        pub const AFL_WEAKNAM: u32 = 0x00000008;
        pub const AFL_HIDDEN: u32 = 0x00000010;
        pub const AFL_MANUAL: u32 = 0x00000020;
        pub const AFL_NOBRD: u32 = 0x00000040;
        pub const AFL_ZSTROFF: u32 = 0x00000080;
        pub const AFL_BNOT0: u32 = 0x00000100;
        pub const AFL_BNOT1: u32 = 0x00000200;
        pub const AFL_LIB: u32 = 0x00000400;
        pub const AFL_TI: u32 = 0x00000800;
        pub const AFL_TI0: u32 = 0x00001000;
        pub const AFL_TI1: u32 = 0x00002000;
        pub const AFL_LNAME: u32 = 0x00004000;
        pub const AFL_TILCMT: u32 = 0x00008000;
        pub const AFL_LZERO0: u32 = 0x00010000;
        pub const AFL_LZERO1: u32 = 0x00020000;
        pub const AFL_COLORED: u32 = 0x00040000;
        pub const AFL_TERSESTR: u32 = 0x00080000;
        pub const AFL_SIGN0: u32 = 0x00100000;
        pub const AFL_SIGN1: u32 = 0x00200000;
        pub const AFL_NORET: u32 = 0x00400000;
        pub const AFL_FIXEDSPD: u32 = 0x00800000;
        pub const AFL_ALIGNFLOW: u32 = 0x01000000;
        pub const AFL_USERTI: u32 = 0x02000000;
        pub const AFL_RETFP: u32 = 0x04000000;
        pub const AFL_USEMODSP: u32 = 0x08000000;
        pub const AFL_NOTCODE: u32 = 0x10000000;
    }
}

pub mod name {
    pub use super::ffi::{
        get_nlist_ea, get_nlist_idx, get_nlist_name, get_nlist_size, is_in_nlist, is_public_name,
        is_weak_name,
    };
    pub use super::ffix::{
        idalib_cleanup_name, idalib_del_name, idalib_demangle_name, idalib_dummy_name_ea,
        idalib_force_name, idalib_get_colored_name, idalib_get_long_name, idalib_get_name,
        idalib_get_name_ea, idalib_get_short_name, idalib_get_visible_name, idalib_hide_name,
        idalib_is_ident, idalib_is_uname, idalib_is_valid_typename, idalib_make_name_auto,
        idalib_make_name_non_public, idalib_make_name_non_weak, idalib_make_name_public,
        idalib_make_name_user, idalib_make_name_weak, idalib_rebuild_nlist, idalib_set_dummy_name,
        idalib_set_name, idalib_show_name,
    };
}

pub mod auto {
    pub use super::ffix::{
        idalib_auto_apply_type, idalib_auto_cancel, idalib_auto_is_ok, idalib_auto_make_code,
        idalib_auto_make_proc, idalib_auto_make_step, idalib_auto_mark, idalib_auto_mark_range,
        idalib_auto_recreate_insn, idalib_auto_unmark, idalib_auto_wait_range, idalib_enable_auto,
        idalib_get_auto_state, idalib_is_auto_enabled, idalib_may_create_stkvars,
        idalib_may_trace_sp, idalib_peek_auto_queue, idalib_plan_and_wait, idalib_plan_ea,
        idalib_plan_range, idalib_reanalyze_callers, idalib_revert_ida_decisions,
        idalib_set_auto_state, idalib_set_ida_state,
    };

    /// Auto-analysis queue types
    pub mod queue {
        pub const AU_NONE: i32 = 0;
        pub const AU_UNK: i32 = 10;
        pub const AU_CODE: i32 = 20;
        pub const AU_WEAK: i32 = 25;
        pub const AU_PROC: i32 = 30;
        pub const AU_TAIL: i32 = 35;
        pub const AU_FCHUNK: i32 = 38;
        pub const AU_USED: i32 = 40;
        pub const AU_USD2: i32 = 45;
        pub const AU_TYPE: i32 = 50;
        pub const AU_LIBF: i32 = 60;
        pub const AU_LBF2: i32 = 70;
        pub const AU_LBF3: i32 = 80;
        pub const AU_CHLB: i32 = 90;
        pub const AU_FINAL: i32 = 200;
    }

    /// IDA state indicator
    pub mod state {
        pub const ST_READY: i32 = 0;
        pub const ST_THINK: i32 = 1;
        pub const ST_WAITING: i32 = 2;
        pub const ST_WORK: i32 = 3;
    }
}

pub mod frame {
    pub use super::ffix::{
        idalib_add_auto_stkpnt, idalib_add_frame, idalib_add_regvar, idalib_add_user_stkpnt,
        idalib_build_stkvar_name, idalib_del_frame, idalib_del_regvar, idalib_del_stkpnt,
        idalib_frame_off_args, idalib_frame_off_lvars, idalib_frame_off_retaddr,
        idalib_frame_off_savregs, idalib_func_argsize, idalib_func_fpd, idalib_func_frregs,
        idalib_func_frsize, idalib_get_effective_spd, idalib_get_frame_part_args,
        idalib_get_frame_part_lvars, idalib_get_frame_part_retaddr, idalib_get_frame_part_savregs,
        idalib_get_frame_retsize, idalib_get_frame_size, idalib_get_sp_delta, idalib_get_spd,
        idalib_has_regvar, idalib_set_auto_spd, idalib_set_frame_size, idalib_set_purged,
        idalib_update_fpd,
    };
}

pub mod fixup {
    pub use super::ffix::{
        idalib_apply_fixup, idalib_calc_fixup_size, idalib_contains_fixups, idalib_del_fixup,
        idalib_exists_fixup, idalib_get_first_fixup_ea, idalib_get_fixup, idalib_get_fixup_desc,
        idalib_get_fixup_value, idalib_get_next_fixup_ea, idalib_get_prev_fixup_ea,
        idalib_is_fixup_custom, idalib_set_fixup,
    };

    /// Fixup types
    pub mod types {
        pub const FIXUP_OFF8: u16 = 13;
        pub const FIXUP_OFF16: u16 = 1;
        pub const FIXUP_SEG16: u16 = 2;
        pub const FIXUP_PTR16: u16 = 3;
        pub const FIXUP_OFF32: u16 = 4;
        pub const FIXUP_PTR32: u16 = 5;
        pub const FIXUP_HI8: u16 = 6;
        pub const FIXUP_HI16: u16 = 7;
        pub const FIXUP_LOW8: u16 = 8;
        pub const FIXUP_LOW16: u16 = 9;
        pub const FIXUP_OFF64: u16 = 12;
        pub const FIXUP_OFF8S: u16 = 14;
        pub const FIXUP_OFF16S: u16 = 15;
        pub const FIXUP_OFF32S: u16 = 16;
        pub const FIXUP_CUSTOM: u16 = 0x8000;
    }

    /// Fixup flags
    pub mod flags {
        pub const FIXUPF_REL: u32 = 0x0001;
        pub const FIXUPF_EXTDEF: u32 = 0x0002;
        pub const FIXUPF_UNUSED: u32 = 0x0004;
        pub const FIXUPF_CREATED: u32 = 0x0008;
    }
}

pub mod lines {
    pub use super::ffix::{
        idalib_add_extra_cmt, idalib_add_extra_line, idalib_add_pgm_cmt, idalib_add_sourcefile,
        idalib_calc_bg_color, idalib_calc_prefix_color, idalib_del_extra_cmt,
        idalib_del_sourcefile, idalib_delete_extra_cmts, idalib_generate_disasm_line,
        idalib_generate_disasm_line_no_tags, idalib_generate_disassembly, idalib_get_extra_cmt,
        idalib_get_sourcefile, idalib_tag_remove, idalib_tag_strlen,
    };

    /// Disassembly generation flags
    pub mod flags {
        pub const GENDSM_FORCE_CODE: i32 = 1;
        pub const GENDSM_MULTI_LINE: i32 = 2;
        pub const GENDSM_REMOVE_TAGS: i32 = 4;
        pub const GENDSM_UNHIDE: i32 = 8;
    }

    /// Extra lines constants
    pub mod extra {
        pub const E_PREV: i32 = 1000;
        pub const E_NEXT: i32 = 2000;
    }
}

pub mod ida {
    use std::env;
    use std::ffi::CString;
    use std::path::Path;
    use std::ptr;

    use autocxx::prelude::*;

    use super::platform::is_main_thread;
    use super::{IDAError, ea_t, ffi, ffix};

    pub use ffi::auto_wait;

    pub fn is_license_valid() -> bool {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        unsafe { ffix::idalib_check_license() }
    }

    pub fn license_id() -> Result<[u8; 6], IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        let mut lid = [0u8; 6];
        if unsafe { ffix::idalib_get_license_id(&mut lid) } {
            Ok(lid)
        } else {
            Err(IDAError::InvalidLicense)
        }
    }

    // NOTE: once; main thread
    pub fn init_library() -> Result<(), IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        unsafe { env::set_var("TVHEADLESS", "1") };

        let res = unsafe { ffix::init_library(c_int(0), ptr::null_mut()) };

        if res != c_int(0) {
            Err(IDAError::Init(res))
        } else {
            Ok(())
        }
    }

    pub fn make_signatures(only_pat: bool) -> Result<(), IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        if unsafe { ffi::make_signatures(only_pat) } {
            Ok(())
        } else {
            Err(IDAError::MakeSigs)
        }
    }

    pub fn enable_console_messages(enable: bool) {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        unsafe { ffi::enable_console_messages(enable) }
    }

    pub fn set_screen_ea(ea: ea_t) {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        unsafe { ffi::set_screen_ea(ea) }
    }

    pub fn open_database(path: impl AsRef<Path>) -> Result<(), IDAError> {
        open_database_with(path, true)
    }

    // NOTE: main thread
    pub fn open_database_with(path: impl AsRef<Path>, auto_analysis: bool) -> Result<(), IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        if !is_license_valid() {
            return Err(IDAError::InvalidLicense);
        }

        let path = CString::new(path.as_ref().to_string_lossy().as_ref()).map_err(IDAError::ffi)?;

        let res = unsafe { ffi::open_database(path.as_ptr(), auto_analysis, std::ptr::null()) };

        if res != c_int(0) {
            Err(IDAError::OpenDb(res))
        } else {
            Ok(())
        }
    }

    pub fn open_database_quiet(
        path: impl AsRef<Path>,
        auto_analysis: bool,
        args: &[impl AsRef<str>],
    ) -> Result<(), IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        if !is_license_valid() {
            return Err(IDAError::InvalidLicense);
        }

        let mut args = args
            .iter()
            .map(|s| CString::new(s.as_ref()).map_err(IDAError::ffi))
            .collect::<Result<Vec<_>, _>>()?;

        let path = CString::new(path.as_ref().to_string_lossy().as_ref()).map_err(IDAError::ffi)?;
        args.push(path);

        let argv = std::iter::once(c"idalib".as_ptr())
            .chain(args.iter().map(|s| s.as_ptr()))
            .collect::<Vec<_>>();
        let argc = argv.len();

        let res = unsafe {
            ffix::idalib_open_database_quiet(c_int(argc as _), argv.as_ptr(), auto_analysis)
        };

        if res != c_int(0) {
            Err(IDAError::OpenDb(res))
        } else {
            Ok(())
        }
    }

    pub fn close_database() {
        close_database_with(true);
    }

    pub fn close_database_with(save: bool) {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        unsafe { ffi::close_database(save) }
    }

    pub fn library_version() -> Result<(i32, i32, i32), IDAError> {
        assert!(
            is_main_thread(),
            "IDA cannot function correctly when not running on the main thread"
        );

        let mut major = c_int(0);
        let mut minor = c_int(0);
        let mut build = c_int(0);

        if unsafe { ffix::idalib_get_library_version(&mut major, &mut minor, &mut build) } {
            Ok((major.0 as _, minor.0 as _, build.0 as _))
        } else {
            Err(IDAError::GetVersion)
        }
    }
}

pub mod typeinf {
    pub use super::ffix::{
        idalib_add_local_type, idalib_add_til, idalib_del_local_type, idalib_del_til,
        idalib_del_tinfo_at, idalib_get_abi_name_str, idalib_get_compiler_abbr_str,
        idalib_get_compiler_id, idalib_get_compiler_name_str, idalib_get_enum_member_count,
        idalib_get_enum_member_name, idalib_get_enum_member_value, idalib_get_func_arg_count,
        idalib_get_func_arg_name, idalib_get_func_arg_type, idalib_get_func_cc,
        idalib_get_func_rettype, idalib_get_func_type_str, idalib_get_named_type_ordinal,
        idalib_get_named_type_size, idalib_get_named_type_str, idalib_get_numbered_type_str,
        idalib_get_op_type_str, idalib_get_ordinal_qty, idalib_get_type_size, idalib_get_type_str,
        idalib_get_udt_member_count, idalib_get_udt_member_name, idalib_get_udt_member_offset,
        idalib_get_udt_member_type, idalib_is_type_array, idalib_is_type_enum, idalib_is_type_func,
        idalib_is_type_ptr, idalib_is_type_struct, idalib_is_type_union, idalib_named_type_exists,
        idalib_parse_decl, idalib_print_type, idalib_set_func_type_str, idalib_set_op_type_str,
        idalib_set_type_str,
    };

    /// Calling conventions
    pub mod cc {
        pub const CM_CC_INVALID: i32 = 0x00;
        pub const CM_CC_UNKNOWN: i32 = 0x10;
        pub const CM_CC_VOIDARG: i32 = 0x20;
        pub const CM_CC_CDECL: i32 = 0x30;
        pub const CM_CC_ELLIPSIS: i32 = 0x40;
        pub const CM_CC_STDCALL: i32 = 0x50;
        pub const CM_CC_PASCAL: i32 = 0x60;
        pub const CM_CC_FASTCALL: i32 = 0x70;
        pub const CM_CC_THISCALL: i32 = 0x80;
        pub const CM_CC_MANUAL: i32 = 0x90;
        pub const CM_CC_SPOILED: i32 = 0xA0;
        pub const CM_CC_GOLANG: i32 = 0xB0;
        pub const CM_CC_RESERVE4: i32 = 0xC0;
        pub const CM_CC_RESERVE3: i32 = 0xD0;
        pub const CM_CC_SPECIALE: i32 = 0xE0;
        pub const CM_CC_SPECIALP: i32 = 0xF0;
    }

    /// Print type flags
    pub mod prtype {
        pub const PRTYPE_1LINE: i32 = 0x00000;
        pub const PRTYPE_MULTI: i32 = 0x00001;
        pub const PRTYPE_TYPE: i32 = 0x00002;
        pub const PRTYPE_PRAGMA: i32 = 0x00004;
        pub const PRTYPE_SEMI: i32 = 0x00008;
        pub const PRTYPE_CPP: i32 = 0x00010;
        pub const PRTYPE_DEF: i32 = 0x00020;
        pub const PRTYPE_NOARGS: i32 = 0x00040;
        pub const PRTYPE_NOARRS: i32 = 0x00080;
        pub const PRTYPE_NORES: i32 = 0x00100;
        pub const PRTYPE_RESTORE: i32 = 0x00200;
        pub const PRTYPE_COLORED: i32 = 0x00400;
        pub const PRTYPE_METHODS: i32 = 0x01000;
    }
}

pub mod problems {
    pub use super::ffix::{
        idalib_forget_problem, idalib_get_problem, idalib_get_problem_desc,
        idalib_get_problem_name, idalib_is_problem_present, idalib_remember_problem,
    };

    /// Problem types
    pub mod types {
        pub const PR_NOBASE: i32 = 65; // 'A' - can't find offset base
        pub const PR_NONAME: i32 = 78; // 'N' - can't find name
        pub const PR_NOFOP: i32 = 79; // 'O' - can't find forced operand
        pub const PR_NOCMT: i32 = 67; // 'C' - can't find comment
        pub const PR_NOXREFS: i32 = 88; // 'X' - can't find xrefs
        pub const PR_JUMP: i32 = 74; // 'J' - jump table is not found
        pub const PR_DISASM: i32 = 81; // 'Q' - disassembly problem
        pub const PR_HEAD: i32 = 72; // 'H' - data in the middle of instruction
        pub const PR_ILLADDR: i32 = 73; // 'I' - illegal address
        pub const PR_MANYLINES: i32 = 76; // 'L' - too many lines
        pub const PR_BADSTACK: i32 = 83; // 'S' - stack problems
        pub const PR_ATTN: i32 = 33; // '!' - attention
        pub const PR_FINAL: i32 = 70; // 'F' - final problems
        pub const PR_ROLLED: i32 = 82; // 'R' - rolled up addresses
        pub const PR_COLLISION: i32 = 68; // 'D' - collision
    }
}

pub mod offset {
    pub use super::ffix::{
        idalib_calc_offset_base, idalib_calc_probable_base_by_value, idalib_can_be_off32,
        idalib_del_refinfo, idalib_get_default_reftype, idalib_get_offset_expression,
        idalib_get_refinfo, idalib_op_offset, idalib_set_refinfo,
    };

    /// Reference types
    pub mod reftypes {
        pub const REF_OFF8: i32 = 0;
        pub const REF_OFF16: i32 = 1;
        pub const REF_OFF32: i32 = 2;
        pub const REF_LOW8: i32 = 3;
        pub const REF_LOW16: i32 = 4;
        pub const REF_HIGH8: i32 = 5;
        pub const REF_HIGH16: i32 = 6;
        pub const REF_VHIGH: i32 = 7;
        pub const REF_VLOW: i32 = 8;
        pub const REF_OFF64: i32 = 9;
        pub const REF_OFF8S: i32 = 10;
        pub const REF_OFF16S: i32 = 11;
        pub const REF_OFF32S: i32 = 12;
    }
}

pub mod segregs {
    pub use super::ffix::{
        idalib_del_sreg_range, idalib_get_prev_sreg_range, idalib_get_sreg, idalib_get_sreg_range,
        idalib_get_sreg_ranges_qty, idalib_set_default_dataseg, idalib_set_default_sreg_value,
        idalib_set_sreg_at_next_code, idalib_split_sreg_range,
    };

    /// Segment register tags
    pub mod tags {
        pub const SR_inherit: i32 = 0;
        pub const SR_user: i32 = 1;
        pub const SR_auto: i32 = 2;
        pub const SR_autostart: i32 = 3;
    }
}

pub mod tryblks {
    pub use super::ffix::{
        idalib_del_tryblks, idalib_find_syseh, idalib_get_tryblks_qty, idalib_is_ea_tryblks,
    };

    /// Try block flags for is_ea_tryblks
    pub mod flags {
        pub const TBEA_TRY: u32 = 0x0001;
        pub const TBEA_CATCH: u32 = 0x0002;
        pub const TBEA_SEHTRY: u32 = 0x0004;
        pub const TBEA_SEHFILT: u32 = 0x0008;
        pub const TBEA_ANY: u32 = 0x000F;
        pub const TBEA_FALLTHRU: u32 = 0x0010;
    }
}

pub mod netnode {
    pub use super::ffix::{
        idalib_ea2node, idalib_netnode_altdel, idalib_netnode_altset, idalib_netnode_altval,
        idalib_netnode_blobsize, idalib_netnode_create, idalib_netnode_delblob,
        idalib_netnode_delvalue, idalib_netnode_find, idalib_netnode_get_name,
        idalib_netnode_hashdel, idalib_netnode_hashfirst, idalib_netnode_hashnext,
        idalib_netnode_hashset, idalib_netnode_hashset_long, idalib_netnode_hashstr,
        idalib_netnode_hashval_long, idalib_netnode_inited, idalib_netnode_kill,
        idalib_netnode_rename, idalib_netnode_set_value, idalib_netnode_setblob,
        idalib_netnode_supdel, idalib_netnode_supdel_all, idalib_netnode_supfirst,
        idalib_netnode_suplast, idalib_netnode_supnext, idalib_netnode_supprev,
        idalib_netnode_supset, idalib_netnode_supstr, idalib_netnode_supval, idalib_netnode_valstr,
        idalib_node2ea,
    };

    /// Common netnode tags
    pub mod tags {
        pub const ATAG: i32 = b'A' as i32; // altvals
        pub const STAG: i32 = b'S' as i32; // supvals
        pub const HTAG: i32 = b'H' as i32; // hashvals
        pub const VTAG: i32 = b'V' as i32; // node value (blob)
        pub const NTAG: i32 = b'N' as i32; // netnode name
    }

    /// Special netnode index
    pub const BADNODE: u64 = u64::MAX;
}
