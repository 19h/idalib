#pragma once

#include "hexrays.hpp"
#include "lines.hpp"
#include "pro.h"

#include <cstdint>
#include <memory>
#include <sstream>

#include "cxx.h"

#ifndef CXXBRIDGE1_STRUCT_hexrays_error_t
#define CXXBRIDGE1_STRUCT_hexrays_error_t
struct hexrays_error_t final {
  ::std::int32_t code;
  ::std::uint64_t addr;
  ::rust::String desc;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_hexrays_error_t

// ============================================================================
// Iterators
// ============================================================================

struct cblock_iter {
  qlist<cinsn_t>::iterator start;
  qlist<cinsn_t>::iterator end;

  cblock_iter(cblock_t *b) : start(b->begin()), end(b->end()) {}
};

struct lvars_iter {
  lvars_t *lvars;
  size_t idx;
  
  lvars_iter(lvars_t *l) : lvars(l), idx(0) {}
};

struct carglist_iter {
  carglist_t *args;
  size_t idx;
  
  carglist_iter(carglist_t *a) : args(a), idx(0) {}
};

// ============================================================================
// Basic decompilation functions
// ============================================================================

inline cfunc_t *idalib_hexrays_cfuncptr_inner(const cfuncptr_t *f) { return *f; }

inline std::unique_ptr<cfuncptr_t>
idalib_hexrays_decompile_func(func_t *f, hexrays_error_t *err, int flags) {
  hexrays_failure_t failure;
  cfuncptr_t cf = decompile_func(f, &failure, flags);

  if (failure.code >= 0 && cf != nullptr) {
    return std::unique_ptr<cfuncptr_t>(new cfuncptr_t(cf));
  }

  err->code = failure.code;
  err->desc = rust::String(failure.desc().c_str());
  err->addr = failure.errea;

  return nullptr;
}

// ============================================================================
// cfunc_t operations - Decompiled function
// ============================================================================

// Get pseudocode as string
inline rust::String idalib_hexrays_cfunc_pseudocode(cfunc_t *f) {
  auto sv = f->get_pseudocode();
  auto sb = std::stringstream();

  auto buf = qstring();

  for (int i = 0; i < sv.size(); i++) {
    tag_remove(&buf, sv[i].line);
    sb << buf.c_str() << '\n';
  }

  return rust::String(sb.str());
}

// Get function entry address
inline uint64_t idalib_hexrays_cfunc_entry_ea(const cfunc_t *f) {
  return f->entry_ea;
}

// Get function maturity level
inline int idalib_hexrays_cfunc_maturity(const cfunc_t *f) {
  return static_cast<int>(f->maturity);
}

// Get number of header lines (declaration area)
inline int idalib_hexrays_cfunc_hdrlines(const cfunc_t *f) {
  return f->hdrlines;
}

// Print function declaration
inline rust::String idalib_hexrays_cfunc_print_dcl(const cfunc_t *f) {
  qstring out;
  f->print_dcl(&out);
  return rust::String(out.c_str());
}

// Get function type as string
inline rust::String idalib_hexrays_cfunc_type_str(const cfunc_t *f) {
  tinfo_t tif;
  if (f->get_func_type(&tif)) {
    qstring out;
    if (tif.print(&out)) {
      return rust::String(out.c_str());
    }
  }
  return rust::String();
}

// Get number of local variables
inline size_t idalib_hexrays_cfunc_lvars_count(cfunc_t *f) {
  lvars_t *vars = f->get_lvars();
  return vars ? vars->size() : 0;
}

// Get local variables iterator
inline std::unique_ptr<lvars_iter> idalib_hexrays_cfunc_lvars_iter(cfunc_t *f) {
  lvars_t *vars = f->get_lvars();
  if (!vars) return nullptr;
  return std::unique_ptr<lvars_iter>(new lvars_iter(vars));
}

// Get next local variable from iterator
inline lvar_t *idalib_hexrays_lvars_iter_next(lvars_iter &it) {
  if (it.lvars && it.idx < it.lvars->size()) {
    return &((*it.lvars)[it.idx++]);
  }
  return nullptr;
}

// Get number of arguments
inline size_t idalib_hexrays_cfunc_argidx_count(const cfunc_t *f) {
  return f->argidx.size();
}

// Get argument index at position
inline int idalib_hexrays_cfunc_argidx_at(const cfunc_t *f, size_t i) {
  if (i < f->argidx.size()) {
    return f->argidx[i];
  }
  return -1;
}

// Get stack offset delta
inline int64_t idalib_hexrays_cfunc_stkoff_delta(cfunc_t *f) {
  return f->get_stkoff_delta();
}

// Check if function has orphan comments
inline bool idalib_hexrays_cfunc_has_orphan_cmts(const cfunc_t *f) {
  return f->has_orphan_cmts();
}

// Delete orphan comments
inline int idalib_hexrays_cfunc_del_orphan_cmts(cfunc_t *f) {
  return f->del_orphan_cmts();
}

// Get number of warnings
inline size_t idalib_hexrays_cfunc_warnings_count(cfunc_t *f) {
  return f->get_warnings().size();
}

// Get warning at index
inline rust::String idalib_hexrays_cfunc_warning_at(cfunc_t *f, size_t idx) {
  hexwarns_t &warns = f->get_warnings();
  if (idx < warns.size()) {
    return rust::String(warns[idx].text.c_str());
  }
  return rust::String();
}

// Get warning address at index
inline uint64_t idalib_hexrays_cfunc_warning_ea_at(cfunc_t *f, size_t idx) {
  hexwarns_t &warns = f->get_warnings();
  if (idx < warns.size()) {
    return warns[idx].ea;
  }
  return BADADDR;
}

// Find label in ctree
inline citem_t *idalib_hexrays_cfunc_find_label(cfunc_t *f, int label) {
  return f->find_label(label);
}

// Remove unused labels
inline void idalib_hexrays_cfunc_remove_unused_labels(cfunc_t *f) {
  f->remove_unused_labels();
}

// Refresh function text after modifications
inline void idalib_hexrays_cfunc_refresh(cfunc_t *f) {
  f->refresh_func_ctext();
}

// Save user comments to database
inline void idalib_hexrays_cfunc_save_user_cmts(const cfunc_t *f) {
  f->save_user_cmts();
}

// Save user labels to database
inline void idalib_hexrays_cfunc_save_user_labels(const cfunc_t *f) {
  f->save_user_labels();
}

// Save user numforms to database
inline void idalib_hexrays_cfunc_save_user_numforms(const cfunc_t *f) {
  f->save_user_numforms();
}

// Save user iflags to database
inline void idalib_hexrays_cfunc_save_user_iflags(const cfunc_t *f) {
  f->save_user_iflags();
}

// Save user unions to database
inline void idalib_hexrays_cfunc_save_user_unions(const cfunc_t *f) {
  f->save_user_unions();
}

// ============================================================================
// citem_t operations - Base ctree item
// ============================================================================

// Get item address
inline uint64_t idalib_hexrays_citem_ea(const citem_t *item) {
  return item->ea;
}

// Get item opcode
inline int idalib_hexrays_citem_op(const citem_t *item) {
  return static_cast<int>(item->op);
}

// Is expression (vs statement)?
inline bool idalib_hexrays_citem_is_expr(const citem_t *item) {
  return item->is_expr();
}

// Get label number (-1 if no label)
inline int idalib_hexrays_citem_label_num(const citem_t *item) {
  return item->label_num;
}

// Check if item contains a label
inline bool idalib_hexrays_citem_contains_label(const citem_t *item) {
  return item->contains_label();
}

// Print item to string
inline rust::String idalib_hexrays_citem_print(const citem_t *item) {
  qstring out;
  item->print1(&out, nullptr);
  tag_remove(&out);
  return rust::String(out.c_str());
}

// Get ctype name (e.g., "cot_add", "cit_if")
inline rust::String idalib_hexrays_ctype_name(int op) {
  const char *name = get_ctype_name(static_cast<ctype_t>(op));
  return name ? rust::String(name) : rust::String();
}

// ============================================================================
// cexpr_t operations - Expressions
// ============================================================================

// Get expression type as string
inline rust::String idalib_hexrays_cexpr_type_str(const cexpr_t *e) {
  qstring out;
  if (e->type.print(&out)) {
    return rust::String(out.c_str());
  }
  return rust::String();
}

// Get expression type size
inline size_t idalib_hexrays_cexpr_type_size(const cexpr_t *e) {
  return e->type.get_size();
}

// Check if expression type is signed
inline bool idalib_hexrays_cexpr_type_is_signed(const cexpr_t *e) {
  return e->type.is_signed();
}

// Check if expression type is unsigned
inline bool idalib_hexrays_cexpr_type_is_unsigned(const cexpr_t *e) {
  return e->type.is_unsigned();
}

// Check if expression type is pointer
inline bool idalib_hexrays_cexpr_type_is_ptr(const cexpr_t *e) {
  return e->type.is_ptr();
}

// Check if expression type is array
inline bool idalib_hexrays_cexpr_type_is_array(const cexpr_t *e) {
  return e->type.is_array();
}

// Check if expression type is struct
inline bool idalib_hexrays_cexpr_type_is_struct(const cexpr_t *e) {
  return e->type.is_struct();
}

// Check if expression type is union
inline bool idalib_hexrays_cexpr_type_is_union(const cexpr_t *e) {
  return e->type.is_union();
}

// Check if expression type is floating point
inline bool idalib_hexrays_cexpr_type_is_float(const cexpr_t *e) {
  return e->type.is_floating();
}

// Get first operand (x)
inline cexpr_t *idalib_hexrays_cexpr_x(cexpr_t *e) {
  return e->x;
}

// Get second operand (y)
inline cexpr_t *idalib_hexrays_cexpr_y(cexpr_t *e) {
  return e->y;
}

// Get third operand (z) - for ternary
inline cexpr_t *idalib_hexrays_cexpr_z(cexpr_t *e) {
  return e->z;
}

// Get number value (for cot_num)
inline uint64_t idalib_hexrays_cexpr_numval(const cexpr_t *e) {
  if (e->op == cot_num && e->n) {
    return e->n->_value;
  }
  return 0;
}

// Get object EA (for cot_obj)
inline uint64_t idalib_hexrays_cexpr_obj_ea(const cexpr_t *e) {
  if (e->op == cot_obj) {
    return e->obj_ea;
  }
  return BADADDR;
}

// Get variable index (for cot_var)
inline int idalib_hexrays_cexpr_var_idx(const cexpr_t *e) {
  if (e->op == cot_var) {
    return e->v.idx;
  }
  return -1;
}

// Get string value (for cot_str)
inline rust::String idalib_hexrays_cexpr_str(const cexpr_t *e) {
  if (e->op == cot_str && e->string) {
    return rust::String(e->string);
  }
  return rust::String();
}

// Get helper name (for cot_helper)
inline rust::String idalib_hexrays_cexpr_helper(const cexpr_t *e) {
  if (e->op == cot_helper && e->helper) {
    return rust::String(e->helper);
  }
  return rust::String();
}

// Get member offset (for cot_memptr, cot_memref)
inline uint32_t idalib_hexrays_cexpr_member_offset(const cexpr_t *e) {
  if (e->op == cot_memptr || e->op == cot_memref) {
    return e->m;
  }
  return 0;
}

// Get pointer size (for cot_ptr, cot_memptr)
inline int idalib_hexrays_cexpr_ptrsize(const cexpr_t *e) {
  if (e->op == cot_ptr || e->op == cot_memptr) {
    return e->ptrsize;
  }
  return 0;
}

// Get call arguments (for cot_call)
inline carglist_t *idalib_hexrays_cexpr_call_args(cexpr_t *e) {
  if (e->op == cot_call) {
    return e->a;
  }
  return nullptr;
}

// Is nice expression (no comma, insn, or label)?
inline bool idalib_hexrays_cexpr_is_nice(const cexpr_t *e) {
  return e->is_nice_expr();
}

// Is call expression?
inline bool idalib_hexrays_cexpr_is_call(const cexpr_t *e) {
  return e->op == cot_call;
}

// Expression flags
inline uint32_t idalib_hexrays_cexpr_exflags(const cexpr_t *e) {
  return e->exflags;
}

// Check specific expression flags
inline bool idalib_hexrays_cexpr_is_cstr(const cexpr_t *e) {
  return e->is_cstr();
}

inline bool idalib_hexrays_cexpr_is_fpop(const cexpr_t *e) {
  return e->is_fpop();
}

inline bool idalib_hexrays_cexpr_is_undef_val(const cexpr_t *e) {
  return e->is_undef_val();
}

// ============================================================================
// cinsn_t operations - Statements
// ============================================================================

// Get block (for cit_block)
inline cblock_t *idalib_hexrays_cinsn_cblock(cinsn_t *s) {
  if (s->op == cit_block) {
    return s->cblock;
  }
  return nullptr;
}

// Get expression (for cit_expr)
inline cexpr_t *idalib_hexrays_cinsn_cexpr(cinsn_t *s) {
  if (s->op == cit_expr) {
    return s->cexpr;
  }
  return nullptr;
}

// Get if condition (for cit_if)
inline cexpr_t *idalib_hexrays_cinsn_if_cond(cinsn_t *s) {
  if (s->op == cit_if && s->cif) {
    return &(s->cif->expr);
  }
  return nullptr;
}

// Get if-then block (for cit_if)
inline cinsn_t *idalib_hexrays_cinsn_if_then(cinsn_t *s) {
  if (s->op == cit_if && s->cif) {
    return s->cif->ithen;
  }
  return nullptr;
}

// Get if-else block (for cit_if)
inline cinsn_t *idalib_hexrays_cinsn_if_else(cinsn_t *s) {
  if (s->op == cit_if && s->cif) {
    return s->cif->ielse;
  }
  return nullptr;
}

// Get for-init (for cit_for)
inline cexpr_t *idalib_hexrays_cinsn_for_init(cinsn_t *s) {
  if (s->op == cit_for && s->cfor) {
    return &(s->cfor->init);
  }
  return nullptr;
}

// Get for-condition (for cit_for)
inline cexpr_t *idalib_hexrays_cinsn_for_cond(cinsn_t *s) {
  if (s->op == cit_for && s->cfor) {
    return &(s->cfor->expr);
  }
  return nullptr;
}

// Get for-step (for cit_for)
inline cexpr_t *idalib_hexrays_cinsn_for_step(cinsn_t *s) {
  if (s->op == cit_for && s->cfor) {
    return &(s->cfor->step);
  }
  return nullptr;
}

// Get for-body (for cit_for)
inline cinsn_t *idalib_hexrays_cinsn_for_body(cinsn_t *s) {
  if (s->op == cit_for && s->cfor) {
    return s->cfor->body;
  }
  return nullptr;
}

// Get while-condition (for cit_while)
inline cexpr_t *idalib_hexrays_cinsn_while_cond(cinsn_t *s) {
  if (s->op == cit_while && s->cwhile) {
    return &(s->cwhile->expr);
  }
  return nullptr;
}

// Get while-body (for cit_while)
inline cinsn_t *idalib_hexrays_cinsn_while_body(cinsn_t *s) {
  if (s->op == cit_while && s->cwhile) {
    return s->cwhile->body;
  }
  return nullptr;
}

// Get do-condition (for cit_do)
inline cexpr_t *idalib_hexrays_cinsn_do_cond(cinsn_t *s) {
  if (s->op == cit_do && s->cdo) {
    return &(s->cdo->expr);
  }
  return nullptr;
}

// Get do-body (for cit_do)
inline cinsn_t *idalib_hexrays_cinsn_do_body(cinsn_t *s) {
  if (s->op == cit_do && s->cdo) {
    return s->cdo->body;
  }
  return nullptr;
}

// Get return expression (for cit_return)
inline cexpr_t *idalib_hexrays_cinsn_return_expr(cinsn_t *s) {
  if (s->op == cit_return && s->creturn) {
    return &(s->creturn->expr);
  }
  return nullptr;
}

// Get goto label (for cit_goto)
inline int idalib_hexrays_cinsn_goto_label(cinsn_t *s) {
  if (s->op == cit_goto && s->cgoto) {
    return s->cgoto->label_num;
  }
  return -1;
}

// Get switch expression (for cit_switch)
inline cexpr_t *idalib_hexrays_cinsn_switch_expr(cinsn_t *s) {
  if (s->op == cit_switch && s->cswitch) {
    return &(s->cswitch->expr);
  }
  return nullptr;
}

// Get switch case count (for cit_switch)
inline size_t idalib_hexrays_cinsn_switch_cases_count(cinsn_t *s) {
  if (s->op == cit_switch && s->cswitch) {
    return s->cswitch->cases.size();
  }
  return 0;
}

// Check if statement passes execution to next (is ordinary flow)
inline bool idalib_hexrays_cinsn_is_ordinary_flow(const cinsn_t *s) {
  return s->is_ordinary_flow();
}

// Check if statement contains free break
inline bool idalib_hexrays_cinsn_contains_free_break(const cinsn_t *s) {
  return s->contains_free_break();
}

// Check if statement contains free continue
inline bool idalib_hexrays_cinsn_contains_free_continue(const cinsn_t *s) {
  return s->contains_free_continue();
}

// ============================================================================
// cblock_t operations - Block statements
// ============================================================================

inline std::unique_ptr<cblock_iter> idalib_hexrays_cblock_iter(cblock_t *b) {
  return std::unique_ptr<cblock_iter>(new cblock_iter(b));
}

inline cinsn_t *idalib_hexrays_cblock_iter_next(cblock_iter &it) {
  if (it.start != it.end) {
    return &*(it.start++);
  }
  return nullptr;
}

inline std::size_t idalib_hexrays_cblock_len(cblock_t *b) { return b->size(); }

// ============================================================================
// carglist_t operations - Call arguments
// ============================================================================

// Get argument count
inline size_t idalib_hexrays_carglist_count(const carglist_t *args) {
  return args ? args->size() : 0;
}

// Get argument at index
inline carg_t *idalib_hexrays_carglist_at(carglist_t *args, size_t idx) {
  if (args && idx < args->size()) {
    return &((*args)[idx]);
  }
  return nullptr;
}

// Create argument iterator
inline std::unique_ptr<carglist_iter> idalib_hexrays_carglist_iter(carglist_t *args) {
  if (!args) return nullptr;
  return std::unique_ptr<carglist_iter>(new carglist_iter(args));
}

// Get next argument from iterator
inline carg_t *idalib_hexrays_carglist_iter_next(carglist_iter &it) {
  if (it.args && it.idx < it.args->size()) {
    return &((*it.args)[it.idx++]);
  }
  return nullptr;
}

// Get formal type of argument
inline rust::String idalib_hexrays_carg_formal_type_str(const carg_t *arg) {
  if (arg) {
    qstring out;
    if (arg->formal_type.print(&out)) {
      return rust::String(out.c_str());
    }
  }
  return rust::String();
}

// Check if argument is vararg
inline bool idalib_hexrays_carg_is_vararg(const carg_t *arg) {
  return arg ? arg->is_vararg : false;
}

// ============================================================================
// lvar_t operations - Local variables
// ============================================================================

// Get variable name
inline rust::String idalib_hexrays_lvar_name(const lvar_t *v) {
  return rust::String(v->name.c_str());
}

// Get variable type as string
inline rust::String idalib_hexrays_lvar_type_str(const lvar_t *v) {
  qstring out;
  if (v->tif.print(&out)) {
    return rust::String(out.c_str());
  }
  return rust::String();
}

// Get variable comment
inline rust::String idalib_hexrays_lvar_cmt(const lvar_t *v) {
  return rust::String(v->cmt.c_str());
}

// Get variable width (size in bytes)
inline int idalib_hexrays_lvar_width(const lvar_t *v) {
  return v->width;
}

// Get variable definition block
inline int idalib_hexrays_lvar_defblk(const lvar_t *v) {
  return v->defblk;
}

// Get variable definition EA
inline uint64_t idalib_hexrays_lvar_defea(const lvar_t *v) {
  return v->defea;
}

// Check if variable is used
inline bool idalib_hexrays_lvar_is_used(const lvar_t *v) {
  return v->used();
}

// Check if variable has a type
inline bool idalib_hexrays_lvar_is_typed(const lvar_t *v) {
  return v->typed();
}

// Check if variable has a nice name
inline bool idalib_hexrays_lvar_has_nice_name(const lvar_t *v) {
  return v->has_nice_name();
}

// Check if variable has user-defined name
inline bool idalib_hexrays_lvar_has_user_name(const lvar_t *v) {
  return v->has_user_name();
}

// Check if variable has user-defined type
inline bool idalib_hexrays_lvar_has_user_type(const lvar_t *v) {
  return v->has_user_type();
}

// Check if variable is a function argument
inline bool idalib_hexrays_lvar_is_arg(const lvar_t *v) {
  return v->is_arg_var();
}

// Check if variable is the function result
inline bool idalib_hexrays_lvar_is_result(const lvar_t *v) {
  return v->is_result_var();
}

// Check if variable is 'this' argument
inline bool idalib_hexrays_lvar_is_thisarg(const lvar_t *v) {
  return v->is_thisarg();
}

// Check if variable is fake (return var or va_list)
inline bool idalib_hexrays_lvar_is_fake(const lvar_t *v) {
  return v->is_fake_var();
}

// Check if variable is overlapped
inline bool idalib_hexrays_lvar_is_overlapped(const lvar_t *v) {
  return v->is_overlapped_var();
}

// Check if variable is floating point
inline bool idalib_hexrays_lvar_is_floating(const lvar_t *v) {
  return v->is_floating_var();
}

// Check if variable is on stack
inline bool idalib_hexrays_lvar_is_stk_var(const lvar_t *v) {
  return v->is_stk_var();
}

// Check if variable is in a register
inline bool idalib_hexrays_lvar_is_reg_var(const lvar_t *v) {
  return v->is_reg_var();
}

// Get variable's register (if reg var) - returns -1 if not a register var
inline int idalib_hexrays_lvar_get_reg(const lvar_t *v) {
  if (v->is_reg_var()) {
    return v->get_reg1();
  }
  return -1;
}

// Get variable's stack offset (if stack var)
inline int64_t idalib_hexrays_lvar_get_stkoff(const lvar_t *v) {
  if (v->is_stk_var()) {
    return v->get_stkoff();
  }
  return 0;
}

// Check if variable address was taken
inline bool idalib_hexrays_lvar_is_used_byref(const lvar_t *v) {
  return v->is_used_byref();
}

// ============================================================================
// Operator helpers
// ============================================================================

// Get negated relation operator
inline int idalib_hexrays_negated_relation(int op) {
  return static_cast<int>(negated_relation(static_cast<ctype_t>(op)));
}

// Get swapped relation operator
inline int idalib_hexrays_swapped_relation(int op) {
  return static_cast<int>(swapped_relation(static_cast<ctype_t>(op)));
}

// Check if operator is binary
inline bool idalib_hexrays_is_binary_op(int op) {
  return is_binary(static_cast<ctype_t>(op));
}

// Check if operator is unary
inline bool idalib_hexrays_is_unary_op(int op) {
  return is_unary(static_cast<ctype_t>(op));
}

// Check if operator is relational (comparison)
inline bool idalib_hexrays_is_relational_op(int op) {
  return is_relational(static_cast<ctype_t>(op));
}

// Check if operator is assignment
inline bool idalib_hexrays_is_assignment_op(int op) {
  return is_assignment(static_cast<ctype_t>(op));
}

// Check if operator is loop statement
inline bool idalib_hexrays_is_loop_op(int op) {
  return is_loop(static_cast<ctype_t>(op));
}

// Check if operator is lvalue
inline bool idalib_hexrays_is_lvalue_op(int op) {
  return is_lvalue(static_cast<ctype_t>(op));
}

// Check if operator is commutative
inline bool idalib_hexrays_is_commutative_op(int op) {
  return is_commutative(static_cast<ctype_t>(op));
}

// ============================================================================
// Microcode basics (mba_t)
// ============================================================================

// Get microcode from cfunc
inline mba_t *idalib_hexrays_cfunc_mba(cfunc_t *f) {
  return f->mba;
}

// Get number of basic blocks
inline int idalib_hexrays_mba_qty(const mba_t *mba) {
  return mba ? mba->qty : 0;
}

// Get mba entry EA
inline uint64_t idalib_hexrays_mba_entry_ea(const mba_t *mba) {
  return mba ? mba->entry_ea : BADADDR;
}

// Get mba maturity
inline int idalib_hexrays_mba_maturity(const mba_t *mba) {
  return mba ? static_cast<int>(mba->maturity) : 0;
}

// Get basic block by index
inline mblock_t *idalib_hexrays_mba_get_mblock(mba_t *mba, int n) {
  if (mba && n >= 0 && n < mba->qty) {
    return mba->get_mblock(n);
  }
  return nullptr;
}

// ============================================================================
// mblock_t operations - Basic blocks
// ============================================================================

// Get block serial number
inline int idalib_hexrays_mblock_serial(const mblock_t *blk) {
  return blk ? blk->serial : -1;
}

// Get block start address
inline uint64_t idalib_hexrays_mblock_start(const mblock_t *blk) {
  return blk ? blk->start : BADADDR;
}

// Get block end address
inline uint64_t idalib_hexrays_mblock_end(const mblock_t *blk) {
  return blk ? blk->end : BADADDR;
}

// Get block type
inline int idalib_hexrays_mblock_type(const mblock_t *blk) {
  return blk ? static_cast<int>(blk->type) : 0;
}

// Get number of predecessors
inline int idalib_hexrays_mblock_npred(const mblock_t *blk) {
  return blk ? blk->npred() : 0;
}

// Get number of successors
inline int idalib_hexrays_mblock_nsucc(const mblock_t *blk) {
  return blk ? blk->nsucc() : 0;
}

// Get predecessor at index
inline int idalib_hexrays_mblock_pred(const mblock_t *blk, int n) {
  if (blk && n >= 0 && n < blk->npred()) {
    return blk->pred(n);
  }
  return -1;
}

// Get successor at index
inline int idalib_hexrays_mblock_succ(const mblock_t *blk, int n) {
  if (blk && n >= 0 && n < blk->nsucc()) {
    return blk->succ(n);
  }
  return -1;
}

// Get first instruction in block
inline minsn_t *idalib_hexrays_mblock_head(mblock_t *blk) {
  return blk ? blk->head : nullptr;
}

// Get last instruction in block
inline minsn_t *idalib_hexrays_mblock_tail(mblock_t *blk) {
  return blk ? blk->tail : nullptr;
}

// ============================================================================
// minsn_t operations - Microcode instructions
// ============================================================================

// Get instruction opcode
inline int idalib_hexrays_minsn_opcode(const minsn_t *insn) {
  return insn ? static_cast<int>(insn->opcode) : 0;
}

// Get instruction address
inline uint64_t idalib_hexrays_minsn_ea(const minsn_t *insn) {
  return insn ? insn->ea : BADADDR;
}

// Get next instruction
inline minsn_t *idalib_hexrays_minsn_next(minsn_t *insn) {
  return insn ? insn->next : nullptr;
}

// Get previous instruction
inline minsn_t *idalib_hexrays_minsn_prev(minsn_t *insn) {
  return insn ? insn->prev : nullptr;
}

// Print microinstruction
inline rust::String idalib_hexrays_minsn_dstr(const minsn_t *insn) {
  if (insn) {
    return rust::String(insn->dstr());
  }
  return rust::String();
}

// Get mcode name (e.g., "mov", "add")
inline rust::String idalib_hexrays_mcode_name(int opcode) {
  // mcode names are not directly exposed, but we can use dstr on a dummy
  // For now, return the numeric value as string
  char buf[32];
  qsnprintf(buf, sizeof(buf), "mcode_%d", opcode);
  return rust::String(buf);
}

// ============================================================================
// Cache management
// ============================================================================

// Mark function dirty (flush from cache)
inline bool idalib_hexrays_mark_cfunc_dirty(uint64_t ea, bool close_views) {
  return mark_cfunc_dirty(ea, close_views);
}

// Clear all cached cfuncs
inline void idalib_hexrays_clear_cached_cfuncs() {
  clear_cached_cfuncs();
}

// Check if cfunc is cached
inline bool idalib_hexrays_has_cached_cfunc(uint64_t ea) {
  return has_cached_cfunc(ea);
}

// ============================================================================
// Decompilation flags
// ============================================================================

// These are the DECOMP_* flags - expose them as functions for Rust
inline int idalib_hexrays_decomp_no_wait() { return DECOMP_NO_WAIT; }
inline int idalib_hexrays_decomp_no_cache() { return DECOMP_NO_CACHE; }
inline int idalib_hexrays_decomp_no_frame() { return DECOMP_NO_FRAME; }
inline int idalib_hexrays_decomp_warnings() { return DECOMP_WARNINGS; }
inline int idalib_hexrays_decomp_all_blks() { return DECOMP_ALL_BLKS; }

// ============================================================================
// ctype_t constants - expose as functions
// ============================================================================

// Expression types
inline int idalib_hexrays_cot_empty() { return cot_empty; }
inline int idalib_hexrays_cot_comma() { return cot_comma; }
inline int idalib_hexrays_cot_asg() { return cot_asg; }
inline int idalib_hexrays_cot_asgbor() { return cot_asgbor; }
inline int idalib_hexrays_cot_asgxor() { return cot_asgxor; }
inline int idalib_hexrays_cot_asgband() { return cot_asgband; }
inline int idalib_hexrays_cot_asgadd() { return cot_asgadd; }
inline int idalib_hexrays_cot_asgsub() { return cot_asgsub; }
inline int idalib_hexrays_cot_asgmul() { return cot_asgmul; }
inline int idalib_hexrays_cot_asgsshr() { return cot_asgsshr; }
inline int idalib_hexrays_cot_asgushr() { return cot_asgushr; }
inline int idalib_hexrays_cot_asgshl() { return cot_asgshl; }
inline int idalib_hexrays_cot_asgsdiv() { return cot_asgsdiv; }
inline int idalib_hexrays_cot_asgudiv() { return cot_asgudiv; }
inline int idalib_hexrays_cot_asgsmod() { return cot_asgsmod; }
inline int idalib_hexrays_cot_asgumod() { return cot_asgumod; }
inline int idalib_hexrays_cot_tern() { return cot_tern; }
inline int idalib_hexrays_cot_lor() { return cot_lor; }
inline int idalib_hexrays_cot_land() { return cot_land; }
inline int idalib_hexrays_cot_bor() { return cot_bor; }
inline int idalib_hexrays_cot_xor() { return cot_xor; }
inline int idalib_hexrays_cot_band() { return cot_band; }
inline int idalib_hexrays_cot_eq() { return cot_eq; }
inline int idalib_hexrays_cot_ne() { return cot_ne; }
inline int idalib_hexrays_cot_sge() { return cot_sge; }
inline int idalib_hexrays_cot_uge() { return cot_uge; }
inline int idalib_hexrays_cot_sle() { return cot_sle; }
inline int idalib_hexrays_cot_ule() { return cot_ule; }
inline int idalib_hexrays_cot_sgt() { return cot_sgt; }
inline int idalib_hexrays_cot_ugt() { return cot_ugt; }
inline int idalib_hexrays_cot_slt() { return cot_slt; }
inline int idalib_hexrays_cot_ult() { return cot_ult; }
inline int idalib_hexrays_cot_sshr() { return cot_sshr; }
inline int idalib_hexrays_cot_ushr() { return cot_ushr; }
inline int idalib_hexrays_cot_shl() { return cot_shl; }
inline int idalib_hexrays_cot_add() { return cot_add; }
inline int idalib_hexrays_cot_sub() { return cot_sub; }
inline int idalib_hexrays_cot_mul() { return cot_mul; }
inline int idalib_hexrays_cot_sdiv() { return cot_sdiv; }
inline int idalib_hexrays_cot_udiv() { return cot_udiv; }
inline int idalib_hexrays_cot_smod() { return cot_smod; }
inline int idalib_hexrays_cot_umod() { return cot_umod; }
inline int idalib_hexrays_cot_fadd() { return cot_fadd; }
inline int idalib_hexrays_cot_fsub() { return cot_fsub; }
inline int idalib_hexrays_cot_fmul() { return cot_fmul; }
inline int idalib_hexrays_cot_fdiv() { return cot_fdiv; }
inline int idalib_hexrays_cot_fneg() { return cot_fneg; }
inline int idalib_hexrays_cot_neg() { return cot_neg; }
inline int idalib_hexrays_cot_cast() { return cot_cast; }
inline int idalib_hexrays_cot_lnot() { return cot_lnot; }
inline int idalib_hexrays_cot_bnot() { return cot_bnot; }
inline int idalib_hexrays_cot_ptr() { return cot_ptr; }
inline int idalib_hexrays_cot_ref() { return cot_ref; }
inline int idalib_hexrays_cot_postinc() { return cot_postinc; }
inline int idalib_hexrays_cot_postdec() { return cot_postdec; }
inline int idalib_hexrays_cot_preinc() { return cot_preinc; }
inline int idalib_hexrays_cot_predec() { return cot_predec; }
inline int idalib_hexrays_cot_call() { return cot_call; }
inline int idalib_hexrays_cot_idx() { return cot_idx; }
inline int idalib_hexrays_cot_memref() { return cot_memref; }
inline int idalib_hexrays_cot_memptr() { return cot_memptr; }
inline int idalib_hexrays_cot_num() { return cot_num; }
inline int idalib_hexrays_cot_fnum() { return cot_fnum; }
inline int idalib_hexrays_cot_str() { return cot_str; }
inline int idalib_hexrays_cot_obj() { return cot_obj; }
inline int idalib_hexrays_cot_var() { return cot_var; }
inline int idalib_hexrays_cot_insn() { return cot_insn; }
inline int idalib_hexrays_cot_sizeof() { return cot_sizeof; }
inline int idalib_hexrays_cot_helper() { return cot_helper; }
inline int idalib_hexrays_cot_type() { return cot_type; }
inline int idalib_hexrays_cot_last() { return cot_last; }

// Statement types
inline int idalib_hexrays_cit_empty() { return cit_empty; }
inline int idalib_hexrays_cit_block() { return cit_block; }
inline int idalib_hexrays_cit_expr() { return cit_expr; }
inline int idalib_hexrays_cit_if() { return cit_if; }
inline int idalib_hexrays_cit_for() { return cit_for; }
inline int idalib_hexrays_cit_while() { return cit_while; }
inline int idalib_hexrays_cit_do() { return cit_do; }
inline int idalib_hexrays_cit_switch() { return cit_switch; }
inline int idalib_hexrays_cit_break() { return cit_break; }
inline int idalib_hexrays_cit_continue() { return cit_continue; }
inline int idalib_hexrays_cit_return() { return cit_return; }
inline int idalib_hexrays_cit_goto() { return cit_goto; }
inline int idalib_hexrays_cit_asm() { return cit_asm; }
inline int idalib_hexrays_cit_try() { return cit_try; }
inline int idalib_hexrays_cit_throw() { return cit_throw; }
