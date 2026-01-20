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

// ============================================================================
// Switch cases - use cinsn_t* and indices to avoid exposing ccases_t/ccase_t
// ============================================================================

// Get number of case groups in switch (already exists as idalib_hexrays_cinsn_switch_cases_count)

// Get number of values in a case at index
inline size_t idalib_hexrays_cinsn_switch_case_values_count(cinsn_t *s, size_t case_idx) {
  if (s && s->op == cit_switch && s->cswitch) {
    ccases_t &cases = s->cswitch->cases;
    if (case_idx < cases.size()) {
      return cases[case_idx].values.size();
    }
  }
  return 0;
}

// Get case value at (case_idx, value_idx)
inline uint64_t idalib_hexrays_cinsn_switch_case_value_at(cinsn_t *s, size_t case_idx, size_t val_idx) {
  if (s && s->op == cit_switch && s->cswitch) {
    ccases_t &cases = s->cswitch->cases;
    if (case_idx < cases.size() && val_idx < cases[case_idx].values.size()) {
      return cases[case_idx].values[val_idx];
    }
  }
  return 0;
}

// Get case body (ccase_t inherits from cinsn_t, so the body is the case itself)
inline cinsn_t *idalib_hexrays_cinsn_switch_case_body(cinsn_t *s, size_t case_idx) {
  if (s && s->op == cit_switch && s->cswitch) {
    ccases_t &cases = s->cswitch->cases;
    if (case_idx < cases.size()) {
      return &cases[case_idx];
    }
  }
  return nullptr;
}

// ============================================================================
// Try/Throw (ctry_t / cthrow_t)
// ============================================================================

// Get try block - returns the try body as a cblock_t iterator to first statement
// ctry_t inherits from cblock_t, so the try body IS the ctry_t itself
inline cinsn_t *idalib_hexrays_cinsn_try_first_stmt(cinsn_t *s) {
  if (s && s->op == cit_try && s->ctry && !s->ctry->empty()) {
    return &s->ctry->front();
  }
  return nullptr;
}

// Get number of catch blocks
inline size_t idalib_hexrays_ctry_catches_count(const cinsn_t *s) {
  if (s && s->op == cit_try && s->ctry) {
    return s->ctry->catchs.size();
  }
  return 0;
}

// Get catch block at index - returns first statement in catch block
inline cinsn_t *idalib_hexrays_ctry_catch_at(cinsn_t *s, size_t idx) {
  if (s && s->op == cit_try && s->ctry && idx < s->ctry->catchs.size()) {
    ccatch_t &c = s->ctry->catchs[idx];
    if (!c.empty()) {
      return &c.front();
    }
  }
  return nullptr;
}

// Get catch expression count at catch index
inline size_t idalib_hexrays_ctry_catch_expr_count(const cinsn_t *s, size_t idx) {
  if (s && s->op == cit_try && s->ctry && idx < s->ctry->catchs.size()) {
    return s->ctry->catchs[idx].exprs.size();
  }
  return 0;
}

// Check if catch at index is "catch all" (catches everything)
inline bool idalib_hexrays_ctry_catch_is_catch_all(const cinsn_t *s, size_t idx) {
  if (s && s->op == cit_try && s->ctry && idx < s->ctry->catchs.size()) {
    return s->ctry->catchs[idx].is_catch_all();
  }
  return false;
}

// Get catch object expression at (catch_idx, expr_idx)
inline cexpr_t *idalib_hexrays_ctry_catch_obj_expr(cinsn_t *s, size_t catch_idx, size_t expr_idx) {
  if (s && s->op == cit_try && s->ctry && catch_idx < s->ctry->catchs.size()) {
    ccatch_t &c = s->ctry->catchs[catch_idx];
    if (expr_idx < c.exprs.size()) {
      return &c.exprs[expr_idx].obj;
    }
  }
  return nullptr;
}

// Get throw expression
inline cexpr_t *idalib_hexrays_cinsn_throw_expr(cinsn_t *s) {
  if (s && s->op == cit_throw && s->cthrow) {
    return &s->cthrow->expr;
  }
  return nullptr;
}

// ============================================================================
// Tree navigation
// ============================================================================

// Find parent of item in ctree
inline citem_t *idalib_hexrays_cfunc_find_parent_of(cfunc_t *f, const citem_t *item) {
  if (f && item) {
    return f->body.find_parent_of(item);
  }
  return nullptr;
}

// Find item by address
inline citem_t *idalib_hexrays_cfunc_find_by_ea(cfunc_t *f, uint64_t ea) {
  if (f) {
    return f->body.find_closest_addr(ea);
  }
  return nullptr;
}

// Check if tree contains an expression
inline bool idalib_hexrays_cinsn_contains_expr(const cinsn_t *s, const cexpr_t *e) {
  return s && e && s->contains_expr(e);
}

// Check if expression is child of item  
inline bool idalib_hexrays_cexpr_is_child_of(const cexpr_t *e, const citem_t *parent) {
  return e && parent && e->is_child_of(parent);
}

// Check expression requires lvalue
inline bool idalib_hexrays_cexpr_requires_lvalue(const cexpr_t *parent, const cexpr_t *child) {
  return parent && child && parent->requires_lvalue(child);
}

// Check expressions have equal effect
inline bool idalib_hexrays_cexpr_equal_effect(const cexpr_t *a, const cexpr_t *b) {
  return a && b && a->equal_effect(*b);
}

// ============================================================================
// lvar_t modifications
// ============================================================================

// Set local variable type  
inline bool idalib_hexrays_lvar_set_type(cfunc_t *f, lvar_t *v, const char *type_str) {
  if (!f || !v || !type_str) return false;
  
  tinfo_t tif;
  qstring errbuf;
  if (!parse_decl(&tif, nullptr, nullptr, type_str, PT_VAR | PT_RAWARGS)) {
    return false;
  }
  return v->set_lvar_type(tif);
}

// Rename local variable (sets user-defined name) - uses mba_t::set_lvar_name
inline bool idalib_hexrays_lvar_set_name(cfunc_t *f, lvar_t *v, const char *name) {
  if (!f || !v || !name) return false;
  mba_t *mba = f->mba;
  if (!mba) return false;
  return mba->set_lvar_name(*v, name, CVAR_NAME|CVAR_UNAME);
}

// Set local variable comment
inline void idalib_hexrays_lvar_set_cmt(lvar_t *v, const char *cmt) {
  if (v && cmt) {
    v->cmt = cmt;
  }
}

// Get lvar by index
inline lvar_t *idalib_hexrays_cfunc_lvar_at(cfunc_t *f, size_t idx) {
  if (f) {
    lvars_t *vars = f->get_lvars();
    if (vars && idx < vars->size()) {
      return &(*vars)[idx];
    }
  }
  return nullptr;
}

// Find lvar by name
inline lvar_t *idalib_hexrays_cfunc_find_lvar_by_name(cfunc_t *f, const char *name) {
  if (!f || !name) return nullptr;
  lvars_t *vars = f->get_lvars();
  if (!vars) return nullptr;
  
  for (size_t i = 0; i < vars->size(); i++) {
    if ((*vars)[i].name == name) {
      return &(*vars)[i];
    }
  }
  return nullptr;
}

// ============================================================================
// mop_t operations - Microcode operands
// ============================================================================

// Get operand type (mop_z, mop_r, mop_n, etc.)
inline int idalib_hexrays_mop_type(const mop_t *op) {
  return op ? static_cast<int>(op->t) : 0;
}

// Get operand size
inline int idalib_hexrays_mop_size(const mop_t *op) {
  return op ? op->size : 0;
}

// Get operand as register number (if mop_r)
inline int idalib_hexrays_mop_reg(const mop_t *op) {
  return (op && op->t == mop_r) ? op->r : -1;
}

// Get operand as immediate value (if mop_n)
inline uint64_t idalib_hexrays_mop_nnn_value(const mop_t *op) {
  return (op && op->t == mop_n && op->nnn) ? op->nnn->value : 0;
}

// Get operand as address - for mop_a, returns the address of the pointed operand
// mop_addr_t inherits from mop_t and wraps another mop_t
inline const mop_t *idalib_hexrays_mop_addr_target(const mop_t *op) {
  return (op && op->t == mop_a && op->a) ? op->a : nullptr;
}

// Get operand as stack offset (if mop_S)
inline int64_t idalib_hexrays_mop_stkoff(const mop_t *op) {
  if (op && op->t == mop_S) {
    return op->s->off;
  }
  return 0;
}

// Get operand as local var index (if mop_l)
inline int idalib_hexrays_mop_lvar_idx(const mop_t *op) {
  return (op && op->t == mop_l) ? op->l->idx : -1;
}

// Get operand as global address (if mop_v)
inline uint64_t idalib_hexrays_mop_glbaddr(const mop_t *op) {
  return (op && op->t == mop_v) ? op->g : BADADDR;
}

// Check if operand is a number
inline bool idalib_hexrays_mop_is_number(const mop_t *op) {
  return op && op->t == mop_n;
}

// Check if operand is a register
inline bool idalib_hexrays_mop_is_reg(const mop_t *op) {
  return op && op->t == mop_r;
}

// Check if operand is a stack location
inline bool idalib_hexrays_mop_is_stk(const mop_t *op) {
  return op && op->t == mop_S;
}

// Check if operand is a local variable
inline bool idalib_hexrays_mop_is_lvar(const mop_t *op) {
  return op && op->t == mop_l;
}

// Check if operand is a global
inline bool idalib_hexrays_mop_is_glb(const mop_t *op) {
  return op && op->t == mop_v;
}

// Check if operand is an address  
inline bool idalib_hexrays_mop_is_addr(const mop_t *op) {
  return op && op->t == mop_a;
}

// Check if operand is a sub-instruction
inline bool idalib_hexrays_mop_is_insn(const mop_t *op) {
  return op && op->t == mop_d;
}

// Get sub-instruction (if mop_d)
inline minsn_t *idalib_hexrays_mop_insn(mop_t *op) {
  return (op && op->t == mop_d) ? op->d : nullptr;
}

// Print operand
inline rust::String idalib_hexrays_mop_dstr(const mop_t *op) {
  if (op) {
    return rust::String(op->dstr());
  }
  return rust::String();
}

// ============================================================================
// Extended mop_t predicates and accessors
// ============================================================================

// Check if operand is empty (mop_z)
inline bool idalib_hexrays_mop_empty(const mop_t *op) {
  return op && op->empty();
}

// Check if operand is a global variable
inline bool idalib_hexrays_mop_is_glbvar(const mop_t *op) {
  return op && op->is_glbvar();
}

// Check if operand is a stack variable
inline bool idalib_hexrays_mop_is_stkvar(const mop_t *op) {
  return op && op->is_stkvar();
}

// Check if operand is an argument list (mop_f - call info)
inline bool idalib_hexrays_mop_is_arglist(const mop_t *op) {
  return op && op->is_arglist();
}

// Check if operand is a condition code register
inline bool idalib_hexrays_mop_is_cc(const mop_t *op) {
  return op && op->is_cc();
}

// Check if operand is a block reference
inline bool idalib_hexrays_mop_is_mblock(const mop_t *op) {
  return op && op->is_mblock();
}

// Check if operand is scattered
inline bool idalib_hexrays_mop_is_scattered(const mop_t *op) {
  return op && op->is_scattered();
}

// Check if operand is address of global
inline bool idalib_hexrays_mop_is_glbaddr(const mop_t *op) {
  return op && op->is_glbaddr();
}

// Check if operand is address of stack variable
inline bool idalib_hexrays_mop_is_stkaddr(const mop_t *op) {
  return op && op->is_stkaddr();
}

// Check if operand is a helper function name
inline bool idalib_hexrays_mop_is_helper(const mop_t *op) {
  return op && op->t == mop_h;
}

// Check if operand is a string literal
inline bool idalib_hexrays_mop_is_strlit(const mop_t *op) {
  return op && op->t == mop_str;
}

// Check if operand is a floating point constant
inline bool idalib_hexrays_mop_is_fpconst(const mop_t *op) {
  return op && op->t == mop_fn;
}

// Check if operand is a pair
inline bool idalib_hexrays_mop_is_pair(const mop_t *op) {
  return op && op->t == mop_p;
}

// Check if operand is switch cases
inline bool idalib_hexrays_mop_is_cases(const mop_t *op) {
  return op && op->t == mop_c;
}

// ============================================================================
// mop_t value tests
// ============================================================================

// Check if operand is a constant and optionally get its value
inline bool idalib_hexrays_mop_is_constant(const mop_t *op, uint64_t *out_value) {
  if (!op) return false;
  uint64 val;
  bool result = op->is_constant(&val, true);
  if (result && out_value) {
    *out_value = val;
  }
  return result;
}

// Check if operand is zero
inline bool idalib_hexrays_mop_is_zero(const mop_t *op) {
  return op && op->is_zero();
}

// Check if operand is one
inline bool idalib_hexrays_mop_is_one(const mop_t *op) {
  return op && op->is_one();
}

// Check if operand is a positive constant
inline bool idalib_hexrays_mop_is_positive_constant(const mop_t *op) {
  return op && op->is_positive_constant();
}

// Check if operand is a negative constant
inline bool idalib_hexrays_mop_is_negative_constant(const mop_t *op) {
  return op && op->is_negative_constant();
}

// Check if values are only 0 and 1
inline bool idalib_hexrays_mop_is01(const mop_t *op) {
  return op && op->is01();
}

// Check if operand has side effects
inline bool idalib_hexrays_mop_has_side_effects(const mop_t *op, bool include_ldx) {
  return op && op->has_side_effects(include_ldx);
}

// ============================================================================
// mop_t properties
// ============================================================================

// Get operand properties (oprops field)
inline int idalib_hexrays_mop_oprops(const mop_t *op) {
  return op ? op->oprops : 0;
}

// Get value number
inline int idalib_hexrays_mop_valnum(const mop_t *op) {
  return op ? op->valnum : 0;
}

// Check if operand is a UDT (struct/union)
inline bool idalib_hexrays_mop_is_udt(const mop_t *op) {
  return op && op->is_udt();
}

// Check if operand is probably floating point
inline bool idalib_hexrays_mop_probably_floating(const mop_t *op) {
  return op && op->probably_floating();
}

// Check if operand uses undefined value
inline bool idalib_hexrays_mop_is_undef_val(const mop_t *op) {
  return op && op->is_undef_val();
}

// Check if operand is a low address offset
inline bool idalib_hexrays_mop_is_lowaddr(const mop_t *op) {
  return op && op->is_lowaddr();
}

// ============================================================================
// mop_t value accessors
// ============================================================================

// Get helper function name (for mop_h)
inline rust::String idalib_hexrays_mop_helper_name(const mop_t *op) {
  if (op && op->t == mop_h && op->helper) {
    return rust::String(op->helper);
  }
  return rust::String();
}

// Get string literal value (for mop_str)
inline rust::String idalib_hexrays_mop_strlit(const mop_t *op) {
  if (op && op->t == mop_str && op->cstr) {
    return rust::String(op->cstr);
  }
  return rust::String();
}

// Get block reference number (for mop_b)
inline int idalib_hexrays_mop_blkref(const mop_t *op) {
  if (op && op->t == mop_b) {
    return op->b;
  }
  return -1;
}

// Get signed value for number operand
inline int64_t idalib_hexrays_mop_signed_value(const mop_t *op) {
  if (op && op->t == mop_n && op->nnn) {
    return op->signed_value();
  }
  return 0;
}

// Get unsigned value for number operand
inline uint64_t idalib_hexrays_mop_unsigned_value(const mop_t *op) {
  if (op && op->t == mop_n && op->nnn) {
    return op->unsigned_value();
  }
  return 0;
}

// ============================================================================
// mop_pair_t accessors (for mop_p operands)
// ============================================================================

// Get the low operand of a pair
inline mop_t *idalib_hexrays_mop_pair_low(mop_t *op) {
  if (op && op->t == mop_p && op->pair) {
    return &op->pair->lop;
  }
  return nullptr;
}

// Get the high operand of a pair
inline mop_t *idalib_hexrays_mop_pair_high(mop_t *op) {
  if (op && op->t == mop_p && op->pair) {
    return &op->pair->hop;
  }
  return nullptr;
}

// ============================================================================
// mcallinfo_t accessors (for mop_f operands - call info)
// ============================================================================

// Get the callee address
inline uint64_t idalib_hexrays_mop_call_callee(const mop_t *op) {
  if (op && op->t == mop_f && op->f) {
    return op->f->callee;
  }
  return BADADDR;
}

// Get the number of call arguments
inline int idalib_hexrays_mop_call_args_count(const mop_t *op) {
  if (op && op->t == mop_f && op->f) {
    return (int)op->f->args.size();
  }
  return 0;
}

// Get the number of solid (non-variadic) arguments
inline int idalib_hexrays_mop_call_solid_args(const mop_t *op) {
  if (op && op->t == mop_f && op->f) {
    return op->f->solid_args;
  }
  return 0;
}

// Check if call is to variadic function
inline bool idalib_hexrays_mop_call_is_vararg(const mop_t *op) {
  if (op && op->t == mop_f && op->f) {
    return op->f->is_vararg();
  }
  return false;
}

// Get call info flags
inline int idalib_hexrays_mop_call_flags(const mop_t *op) {
  if (op && op->t == mop_f && op->f) {
    return op->f->flags;
  }
  return 0;
}

// Check if call doesn't return
inline bool idalib_hexrays_mop_call_is_noret(const mop_t *op) {
  if (op && op->t == mop_f && op->f) {
    return (op->f->flags & FCI_NORET) != 0;
  }
  return false;
}

// Check if call is to pure function
inline bool idalib_hexrays_mop_call_is_pure(const mop_t *op) {
  if (op && op->t == mop_f && op->f) {
    return (op->f->flags & FCI_PURE) != 0;
  }
  return false;
}

// Check if call has no side effects
inline bool idalib_hexrays_mop_call_is_noside(const mop_t *op) {
  if (op && op->t == mop_f && op->f) {
    return (op->f->flags & FCI_NOSIDE) != 0;
  }
  return false;
}

// Get return type as string
inline rust::String idalib_hexrays_mop_call_return_type(const mop_t *op) {
  if (op && op->t == mop_f && op->f) {
    qstring out;
    op->f->return_type.print(&out);
    return rust::String(out.c_str());
  }
  return rust::String();
}

// Get call argument at index (returns the operand)
inline mop_t *idalib_hexrays_mop_call_arg_at(mop_t *op, int idx) {
  if (op && op->t == mop_f && op->f && idx >= 0 && idx < (int)op->f->args.size()) {
    return &op->f->args[idx];
  }
  return nullptr;
}

// Get call argument type as string
inline rust::String idalib_hexrays_mop_call_arg_type(const mop_t *op, int idx) {
  if (op && op->t == mop_f && op->f && idx >= 0 && idx < (int)op->f->args.size()) {
    qstring out;
    op->f->args[idx].type.print(&out);
    return rust::String(out.c_str());
  }
  return rust::String();
}

// Get call argument name
inline rust::String idalib_hexrays_mop_call_arg_name(const mop_t *op, int idx) {
  if (op && op->t == mop_f && op->f && idx >= 0 && idx < (int)op->f->args.size()) {
    return rust::String(op->f->args[idx].name.c_str());
  }
  return rust::String();
}

// Get function role
inline int idalib_hexrays_mop_call_role(const mop_t *op) {
  if (op && op->t == mop_f && op->f) {
    return static_cast<int>(op->f->role);
  }
  return 0; // ROLE_UNK
}

// ============================================================================
// mcases_t accessors (for mop_c operands - switch cases)
// ============================================================================

// Get number of switch cases
inline int idalib_hexrays_mop_cases_count(const mop_t *op) {
  if (op && op->t == mop_c && op->c) {
    return (int)op->c->size();
  }
  return 0;
}

// Get target block for case at index
inline int idalib_hexrays_mop_case_target(const mop_t *op, int idx) {
  if (op && op->t == mop_c && op->c && idx >= 0 && idx < (int)op->c->size()) {
    return op->c->targets[idx];
  }
  return -1;
}

// Get number of values for case at index
inline int idalib_hexrays_mop_case_values_count(const mop_t *op, int idx) {
  if (op && op->t == mop_c && op->c && idx >= 0 && idx < (int)op->c->size()) {
    return (int)op->c->values[idx].size();
  }
  return 0;
}

// Get case value at case_idx, value_idx
inline uint64_t idalib_hexrays_mop_case_value(const mop_t *op, int case_idx, int val_idx) {
  if (op && op->t == mop_c && op->c && 
      case_idx >= 0 && case_idx < (int)op->c->size() &&
      val_idx >= 0 && val_idx < (int)op->c->values[case_idx].size()) {
    return op->c->values[case_idx][val_idx];
  }
  return 0;
}

// ============================================================================
// minsn_t additional operations
// ============================================================================

// Get left operand
inline mop_t *idalib_hexrays_minsn_l(minsn_t *insn) {
  return insn ? &insn->l : nullptr;
}

// Get right operand
inline mop_t *idalib_hexrays_minsn_r(minsn_t *insn) {
  return insn ? &insn->r : nullptr;
}

// Get destination operand
inline mop_t *idalib_hexrays_minsn_d(minsn_t *insn) {
  return insn ? &insn->d : nullptr;
}

// Check if instruction is a call
inline bool idalib_hexrays_minsn_is_call(const minsn_t *insn) {
  return insn && (insn->opcode == m_call || insn->opcode == m_icall);
}

// Check if instruction is a jump
inline bool idalib_hexrays_minsn_is_jump(const minsn_t *insn) {
  return insn && (insn->opcode == m_goto || 
                  insn->opcode == m_jcnd ||
                  insn->opcode == m_jtbl);
}

// Check if instruction is conditional
inline bool idalib_hexrays_minsn_is_cond(const minsn_t *insn) {
  return insn && insn->opcode == m_jcnd;
}

// Check if instruction modifies d operand  
inline bool idalib_hexrays_minsn_modifies_d(const minsn_t *insn) {
  return insn && mcode_modifies_d(insn->opcode);
}

// Find call instruction in block starting from insn
inline minsn_t *idalib_hexrays_minsn_find_call(minsn_t *insn, bool with_helpers) {
  return insn ? insn->find_call(with_helpers) : nullptr;
}

// ============================================================================
// mba_t additional operations  
// ============================================================================

// Get stack frame size
inline int64_t idalib_hexrays_mba_stacksize(const mba_t *mba) {
  return mba ? mba->stacksize : 0;
}

// Get number of arguments
inline int idalib_hexrays_mba_argidx_size(const mba_t *mba) {
  return mba ? mba->argidx.size() : 0;
}

// Get min/max addresses
inline uint64_t idalib_hexrays_mba_minea(const mba_t *mba) {
  return mba ? mba->mbr.start() : BADADDR;
}

// Get the first epilog address
inline uint64_t idalib_hexrays_mba_first_epilog_ea(const mba_t *mba) {
  return mba ? mba->first_epilog_ea : BADADDR;
}

// Check mba flags - use the accessor methods since flags is private
inline bool idalib_hexrays_mba_is_thunk(const mba_t *mba) {
  return mba && mba->is_thunk();
}

inline bool idalib_hexrays_mba_is_short(const mba_t *mba) {
  return mba && mba->short_display();
}

inline bool idalib_hexrays_mba_has_passregs(const mba_t *mba) {
  return mba && mba->has_passregs();
}

// ============================================================================
// Additional cfunc_t operations
// ============================================================================

// Get treeloc info - boundaries (use get_boundaries() to ensure it's initialized)
inline size_t idalib_hexrays_cfunc_boundaries_count(cfunc_t *f) {
  if (!f) return 0;
  boundaries_t &b = f->get_boundaries();
  return b.size();
}

// Get pseudocode line count
inline size_t idalib_hexrays_cfunc_pseudocode_line_count(cfunc_t *f) {
  if (f) {
    auto &sv = f->get_pseudocode();
    return sv.size();
  }
  return 0;
}

// Get pseudocode line at index
inline rust::String idalib_hexrays_cfunc_pseudocode_line_at(cfunc_t *f, size_t idx) {
  if (f) {
    auto &sv = f->get_pseudocode();
    if (idx < sv.size()) {
      qstring buf;
      tag_remove(&buf, sv[idx].line);
      return rust::String(buf.c_str());
    }
  }
  return rust::String();
}

// Get pseudocode line with tags at index
inline rust::String idalib_hexrays_cfunc_pseudocode_line_tagged_at(cfunc_t *f, size_t idx) {
  if (f) {
    auto &sv = f->get_pseudocode();
    if (idx < sv.size()) {
      return rust::String(sv[idx].line.c_str());
    }
  }
  return rust::String();
}

// Get eamap (address to items mapping) count - use get_eamap() to ensure initialized
inline size_t idalib_hexrays_cfunc_eamap_count(cfunc_t *f) {
  if (!f) return 0;
  eamap_t &m = f->get_eamap();
  return m.size();
}

// ============================================================================
// User data management - save/restore
// ============================================================================

// Save user defined labels for function
inline void idalib_hexrays_save_user_labels_ea(uint64_t ea) {
  save_user_labels(ea, nullptr);
}

// Save user defined comments for function
inline void idalib_hexrays_save_user_cmts_ea(uint64_t ea) {
  save_user_cmts(ea, nullptr);
}

// Save user defined number formats for function
inline void idalib_hexrays_save_user_numforms_ea(uint64_t ea) {
  save_user_numforms(ea, nullptr);
}

// Save user defined item flags for function
inline void idalib_hexrays_save_user_iflags_ea(uint64_t ea) {
  save_user_iflags(ea, nullptr);
}

// Save user defined union selections for function
inline void idalib_hexrays_save_user_unions_ea(uint64_t ea) {
  save_user_unions(ea, nullptr);
}

// ============================================================================
// Expression type checking
// ============================================================================

// Check if type is a pointer to function
inline bool idalib_hexrays_cexpr_type_is_funcptr(const cexpr_t *e) {
  if (!e) return false;
  return e->type.is_funcptr();
}

// Check if type is a pointer to void
inline bool idalib_hexrays_cexpr_type_is_pvoid(const cexpr_t *e) {
  return e && e->type.is_pvoid();
}

// Check if type is void
inline bool idalib_hexrays_cexpr_type_is_void(const cexpr_t *e) {
  return e && e->type.is_void();
}

// Check if type is a boolean
inline bool idalib_hexrays_cexpr_type_is_bool(const cexpr_t *e) {
  return e && e->type.is_bool();
}

// Check if type is an enum
inline bool idalib_hexrays_cexpr_type_is_enum(const cexpr_t *e) {
  return e && e->type.is_enum();
}

// Check if type is const
inline bool idalib_hexrays_cexpr_type_is_const(const cexpr_t *e) {
  return e && e->type.is_const();
}

// Check if type is volatile
inline bool idalib_hexrays_cexpr_type_is_volatile(const cexpr_t *e) {
  return e && e->type.is_volatile();
}

// Get pointer depth (0 = not a pointer, 1 = T*, 2 = T**, etc.)
inline int idalib_hexrays_cexpr_type_ptr_depth(const cexpr_t *e) {
  if (!e) return 0;
  int depth = 0;
  tinfo_t t = e->type;
  while (t.is_ptr()) {
    depth++;
    tinfo_t pointed = t.get_pointed_object();
    if (pointed.empty()) break;
    t = pointed;
  }
  return depth;
}

// Get array size if array type
inline int64_t idalib_hexrays_cexpr_type_array_size(const cexpr_t *e) {
  if (!e || !e->type.is_array()) return -1;
  return e->type.get_array_nelems();
}

// Get pointed-to type as string
inline rust::String idalib_hexrays_cexpr_type_pointed_str(const cexpr_t *e) {
  if (e && e->type.is_ptr()) {
    tinfo_t pointed = e->type.get_pointed_object();
    if (!pointed.empty()) {
      qstring out;
      if (pointed.print(&out)) {
        return rust::String(out.c_str());
      }
    }
  }
  return rust::String();
}

// ============================================================================
// Additional citem_t operations
// ============================================================================

// Get item index in parent block (if applicable)
inline int idalib_hexrays_citem_index_in_parent(const cfunc_t *f, const citem_t *item) {
  if (!f || !item) return -1;
  
  const citem_t *parent = f->body.find_parent_of(item);
  if (!parent || !parent->is_expr()) {
    // Check if parent is a block
    if (parent && parent->op == cit_block) {
      const cblock_t *blk = ((const cinsn_t*)parent)->cblock;
      if (blk) {
        int idx = 0;
        for (auto it = blk->begin(); it != blk->end(); ++it, ++idx) {
          if (&(*it) == item) return idx;
        }
      }
    }
  }
  return -1;
}

// ============================================================================
// mcode_t helpers
// ============================================================================

// Get mcode as category
inline int idalib_hexrays_mcode_category(int mcode) {
  // Return general category
  if (mcode >= m_nop && mcode <= m_ext) return 0;  // data operations
  if (mcode >= m_ijmp && mcode <= m_ret) return 1; // control flow
  if (mcode >= m_push && mcode <= m_pop) return 2; // stack
  return 3; // other
}

// Check if mcode modifies memory
inline bool idalib_hexrays_mcode_modifies_mem(int mcode) {
  return mcode == m_stx || mcode == m_push;
}

// Check if mcode reads memory
inline bool idalib_hexrays_mcode_reads_mem(int mcode) {
  return mcode == m_ldx || mcode == m_pop;
}

// Check if mcode is a comparison
inline bool idalib_hexrays_mcode_is_comparison(int mcode) {
  return mcode >= m_sets && mcode <= m_setle;
}

// Check if mcode is arithmetic
inline bool idalib_hexrays_mcode_is_arithmetic(int mcode) {
  return (mcode >= m_add && mcode <= m_udiv) ||
         (mcode >= m_fadd && mcode <= m_fdiv);
}

// Check if mcode is bitwise
inline bool idalib_hexrays_mcode_is_bitwise(int mcode) {
  return mcode == m_and || mcode == m_or || mcode == m_xor;
}

// ============================================================================
// mop_t type constants
// ============================================================================

inline int idalib_hexrays_mop_z() { return mop_z; }  // none
inline int idalib_hexrays_mop_r() { return mop_r; }  // register
inline int idalib_hexrays_mop_n() { return mop_n; }  // immediate number
inline int idalib_hexrays_mop_str() { return mop_str; }  // string constant
inline int idalib_hexrays_mop_d() { return mop_d; }  // result of another instruction
inline int idalib_hexrays_mop_S() { return mop_S; }  // stack variable
inline int idalib_hexrays_mop_v() { return mop_v; }  // global variable
inline int idalib_hexrays_mop_b() { return mop_b; }  // block number
inline int idalib_hexrays_mop_f() { return mop_f; }  // floating point constant
inline int idalib_hexrays_mop_l() { return mop_l; }  // local variable
inline int idalib_hexrays_mop_a() { return mop_a; }  // address of variable
inline int idalib_hexrays_mop_h() { return mop_h; }  // helper function
inline int idalib_hexrays_mop_c() { return mop_c; }  // mcases (switch table)
inline int idalib_hexrays_mop_fn() { return mop_fn; }  // function (for calls)
inline int idalib_hexrays_mop_p() { return mop_p; }  // pair of operands
inline int idalib_hexrays_mop_sc() { return mop_sc; }  // scattered

// ============================================================================
// Additional minsn_t predicates
// ============================================================================

// Instruction property predicates
inline bool idalib_hexrays_minsn_is_tailcall(const minsn_t *m) { return m && m->is_tailcall(); }
inline bool idalib_hexrays_minsn_is_fpinsn(const minsn_t *m) { return m && m->is_fpinsn(); }
inline bool idalib_hexrays_minsn_is_assert(const minsn_t *m) { return m && m->is_assert(); }
inline bool idalib_hexrays_minsn_is_persistent(const minsn_t *m) { return m && m->is_persistent(); }
inline bool idalib_hexrays_minsn_is_combined(const minsn_t *m) { return m && m->is_combined(); }
inline bool idalib_hexrays_minsn_is_farcall(const minsn_t *m) { return m && m->is_farcall(); }
inline bool idalib_hexrays_minsn_is_cleaning_pop(const minsn_t *m) { return m && m->is_cleaning_pop(); }
inline bool idalib_hexrays_minsn_is_propagatable(const minsn_t *m) { return m && m->is_propagatable(); }
inline bool idalib_hexrays_minsn_is_wild_match(const minsn_t *m) { return m && m->is_wild_match(); }
inline bool idalib_hexrays_minsn_was_noret_icall(const minsn_t *m) { return m && m->was_noret_icall(); }
inline bool idalib_hexrays_minsn_is_multimov(const minsn_t *m) { return m && m->is_multimov(); }

// Check if instruction is an unknown call
inline bool idalib_hexrays_minsn_is_unknown_call(const minsn_t *m) {
  return m && m->is_unknown_call();
}

// Get instruction properties flags
inline int idalib_hexrays_minsn_iprops(const minsn_t *m) {
  return m ? m->iprops : 0;
}

// ============================================================================
// Additional mblock_t operations
// ============================================================================

// Check if block ends with a call
inline bool idalib_hexrays_mblock_is_call_block(const mblock_t *blk) {
  return blk && blk->is_call_block();
}

// Check if block is an unknown call
inline bool idalib_hexrays_mblock_is_unknown_call(const mblock_t *blk) {
  return blk && blk->is_unknown_call();
}

// Check if block is nway (switch)
inline bool idalib_hexrays_mblock_is_nway(const mblock_t *blk) {
  return blk && blk->is_nway();
}

// Check if block is a branch (conditional)
inline bool idalib_hexrays_mblock_is_branch(const mblock_t *blk) {
  return blk && blk->is_branch();
}

// Check if block is a simple goto
inline bool idalib_hexrays_mblock_is_simple_goto_block(const mblock_t *blk) {
  return blk && blk->is_simple_goto_block();
}

// Check if block is a simple jcnd
inline bool idalib_hexrays_mblock_is_simple_jcnd_block(const mblock_t *blk) {
  return blk && blk->is_simple_jcnd_block();
}

// Check if block is empty
inline bool idalib_hexrays_mblock_is_empty(const mblock_t *blk) {
  return blk && blk->empty();
}

// Get block flags
inline uint32_t idalib_hexrays_mblock_flags(const mblock_t *blk) {
  return blk ? blk->flags : 0;
}

// Check if block is fake
inline bool idalib_hexrays_mblock_is_fake(const mblock_t *blk) {
  return blk && (blk->flags & MBL_FAKE);
}

// Check if block is goto target
inline bool idalib_hexrays_mblock_is_goto_target(const mblock_t *blk) {
  return blk && (blk->flags & MBL_GOTO);
}

// Check if block is noret (dead end)
inline bool idalib_hexrays_mblock_is_noret(const mblock_t *blk) {
  return blk && (blk->flags & MBL_NORET);
}

// Count instructions in block
inline size_t idalib_hexrays_mblock_insn_count(const mblock_t *blk) {
  if (!blk) return 0;
  size_t count = 0;
  for (const minsn_t *m = blk->head; m != nullptr; m = m->next) {
    count++;
  }
  return count;
}

// ============================================================================
// mcode_t relation helpers
// ============================================================================

// Negate a comparison opcode (e.g., jz -> jnz)
inline int idalib_hexrays_negate_mcode_relation(int mcode) {
  return static_cast<int>(negate_mcode_relation(static_cast<mcode_t>(mcode)));
}

// Swap operands of a comparison opcode (e.g., jl -> jg)
inline int idalib_hexrays_swap_mcode_relation(int mcode) {
  return static_cast<int>(swap_mcode_relation(static_cast<mcode_t>(mcode)));
}

// Get signed version of an unsigned comparison
inline int idalib_hexrays_get_signed_mcode(int mcode) {
  return static_cast<int>(get_signed_mcode(static_cast<mcode_t>(mcode)));
}

// Get unsigned version of a signed comparison
inline int idalib_hexrays_get_unsigned_mcode(int mcode) {
  return static_cast<int>(get_unsigned_mcode(static_cast<mcode_t>(mcode)));
}

// Check if mcode modifies destination
inline bool idalib_hexrays_mcode_modifies_d(int mcode) {
  return mcode_modifies_d(static_cast<mcode_t>(mcode));
}

// Check if mcode is propagatable
inline bool idalib_hexrays_is_mcode_propagatable(int mcode) {
  return is_mcode_propagatable(static_cast<mcode_t>(mcode));
}

// Check if mcode must close a block
inline bool idalib_hexrays_must_mcode_close_block(int mcode, bool including_calls) {
  return must_mcode_close_block(static_cast<mcode_t>(mcode), including_calls);
}

// Check if mcode is a setXX instruction
inline bool idalib_hexrays_mcode_is_set(int mcode) {
  return mcode >= m_sets && mcode <= m_setle;
}

// Check if mcode is a jXX instruction
inline bool idalib_hexrays_mcode_is_jcc(int mcode) {
  return mcode >= m_jcnd && mcode <= m_jle;
}

// Check if mcode is a floating point operation
inline bool idalib_hexrays_mcode_is_fpu(int mcode) {
  return mcode >= m_f2i && mcode <= m_fdiv;
}

// Check if mcode is a call
inline bool idalib_hexrays_mcode_is_call(int mcode) {
  return mcode == m_call || mcode == m_icall;
}

// Check if mcode is a jump
inline bool idalib_hexrays_mcode_is_jump(int mcode) {
  return mcode == m_goto || mcode == m_ijmp || mcode == m_jtbl ||
         (mcode >= m_jcnd && mcode <= m_jle);
}

// Check if mcode is a return
inline bool idalib_hexrays_mcode_is_ret(int mcode) {
  return mcode == m_ret;
}

// ============================================================================
// Additional mba_t operations
// ============================================================================

// Check MBA flags - idalib_hexrays_mba_has_passregs already exists above
inline bool idalib_hexrays_mba_has_calls(const mba_t *mba) {
  return mba && (mba->get_mba_flags() & MBA_CALLS);
}

inline bool idalib_hexrays_mba_is_pattern(const mba_t *mba) {
  return mba && (mba->get_mba_flags() & MBA_PATTERN);
}

inline bool idalib_hexrays_mba_returns_float(const mba_t *mba) {
  return mba && (mba->get_mba_flags() & MBA_RETFP);
}

inline bool idalib_hexrays_mba_has_glbopt(const mba_t *mba) {
  return mba && (mba->get_mba_flags() & MBA_GLBOPT);
}

inline bool idalib_hexrays_mba_is_cmnstk(const mba_t *mba) {
  return mba && (mba->get_mba_flags() & MBA_CMNSTK);
}

// Get MBA flags
inline uint32_t idalib_hexrays_mba_flags(const mba_t *mba) {
  return mba ? mba->get_mba_flags() : 0;
}

// Get final maturity level as int
inline int idalib_hexrays_mba_final_maturity() {
  return static_cast<int>(MMAT_LVARS);
}

// ============================================================================
// merror_t helpers
// ============================================================================

// Get error description
inline rust::String idalib_hexrays_get_merror_desc(int code) {
  qstring out;
  get_merror_desc(&out, static_cast<merror_t>(code), nullptr);
  return rust::String(out.c_str());
}

// Error code constants
inline int idalib_hexrays_merr_ok() { return MERR_OK; }
inline int idalib_hexrays_merr_interr() { return MERR_INTERR; }
inline int idalib_hexrays_merr_insn() { return MERR_INSN; }
inline int idalib_hexrays_merr_mem() { return MERR_MEM; }
inline int idalib_hexrays_merr_badblk() { return MERR_BADBLK; }
inline int idalib_hexrays_merr_badsp() { return MERR_BADSP; }
inline int idalib_hexrays_merr_prolog() { return MERR_PROLOG; }
inline int idalib_hexrays_merr_switch() { return MERR_SWITCH; }
inline int idalib_hexrays_merr_exception() { return MERR_EXCEPTION; }
inline int idalib_hexrays_merr_hugestack() { return MERR_HUGESTACK; }
inline int idalib_hexrays_merr_lvars() { return MERR_LVARS; }
inline int idalib_hexrays_merr_bitness() { return MERR_BITNESS; }
inline int idalib_hexrays_merr_badcall() { return MERR_BADCALL; }
inline int idalib_hexrays_merr_badframe() { return MERR_BADFRAME; }
inline int idalib_hexrays_merr_badidb() { return MERR_BADIDB; }
inline int idalib_hexrays_merr_sizeof() { return MERR_SIZEOF; }
inline int idalib_hexrays_merr_redo() { return MERR_REDO; }
inline int idalib_hexrays_merr_canceled() { return MERR_CANCELED; }
inline int idalib_hexrays_merr_recdepth() { return MERR_RECDEPTH; }
inline int idalib_hexrays_merr_overlap() { return MERR_OVERLAP; }
inline int idalib_hexrays_merr_partinit() { return MERR_PARTINIT; }
inline int idalib_hexrays_merr_complex() { return MERR_COMPLEX; }
inline int idalib_hexrays_merr_license() { return MERR_LICENSE; }
inline int idalib_hexrays_merr_busy() { return MERR_BUSY; }
inline int idalib_hexrays_merr_funcsize() { return MERR_FUNCSIZE; }
inline int idalib_hexrays_merr_badranges() { return MERR_BADRANGES; }
inline int idalib_hexrays_merr_badarch() { return MERR_BADARCH; }

// ============================================================================
// minsn_t iteration helpers
// ============================================================================

// Get next instruction (skip nops)
inline minsn_t *idalib_hexrays_minsn_nexti(const minsn_t *m) {
  if (!m) return nullptr;
  minsn_t *n = m->next;
  while (n && n->opcode == m_nop) {
    n = n->next;
  }
  return n;
}

// Get previous instruction (skip nops)
inline minsn_t *idalib_hexrays_minsn_previ(const minsn_t *m) {
  if (!m) return nullptr;
  minsn_t *p = m->prev;
  while (p && p->opcode == m_nop) {
    p = p->prev;
  }
  return p;
}

// ============================================================================
// Hexrays Callback Infrastructure
// ============================================================================

// Event type constants (matching hexrays_event_t)
inline int idalib_hexrays_hxe_flowchart() { return hxe_flowchart; }
inline int idalib_hexrays_hxe_stkpnts() { return hxe_stkpnts; }
inline int idalib_hexrays_hxe_prolog() { return hxe_prolog; }
inline int idalib_hexrays_hxe_microcode() { return hxe_microcode; }
inline int idalib_hexrays_hxe_preoptimized() { return hxe_preoptimized; }
inline int idalib_hexrays_hxe_locopt() { return hxe_locopt; }
inline int idalib_hexrays_hxe_prealloc() { return hxe_prealloc; }
inline int idalib_hexrays_hxe_glbopt() { return hxe_glbopt; }
inline int idalib_hexrays_hxe_structural() { return hxe_structural; }
inline int idalib_hexrays_hxe_maturity() { return hxe_maturity; }
inline int idalib_hexrays_hxe_interr() { return hxe_interr; }
inline int idalib_hexrays_hxe_combine() { return hxe_combine; }
inline int idalib_hexrays_hxe_print_func() { return hxe_print_func; }
inline int idalib_hexrays_hxe_func_printed() { return hxe_func_printed; }
inline int idalib_hexrays_hxe_resolve_stkaddrs() { return hxe_resolve_stkaddrs; }
inline int idalib_hexrays_hxe_build_callinfo() { return hxe_build_callinfo; }
inline int idalib_hexrays_hxe_calls_done() { return hxe_calls_done; }

// Forward declaration of Rust callback function (defined in Rust with extern "C")
extern "C" int idalib_hexrays_rust_event_handler(
    int event,
    mba_t *mba,
    cfunc_t *cfunc,
    int extra
);

// Global flag to track if callback is installed
static bool g_hexrays_callback_installed = false;

// C++ trampoline callback that dispatches to Rust
static ssize_t idaapi idalib_hexrays_trampoline_callback(
    void *ud,
    hexrays_event_t event,
    va_list va
) {
    mba_t *mba = nullptr;
    cfunc_t *cfunc = nullptr;
    int extra = 0;

    switch (event) {
        case hxe_flowchart: {
            // qflow_chart_t *fc, mba_t *mba, bitset_t *reachable, int decomp_flags
            va_arg(va, void*); // skip fc
            mba = va_arg(va, mba_t*);
            break;
        }
        case hxe_stkpnts:
        case hxe_microcode:
        case hxe_preoptimized:
        case hxe_locopt:
        case hxe_prealloc:
        case hxe_glbopt:
        case hxe_resolve_stkaddrs:
        case hxe_calls_done: {
            // mba_t *mba
            mba = va_arg(va, mba_t*);
            break;
        }
        case hxe_prolog: {
            // mba_t *mba, qflow_chart_t *fc, bitset_t *reachable, int decomp_flags
            mba = va_arg(va, mba_t*);
            break;
        }
        case hxe_maturity: {
            // cfunc_t *cfunc, ctree_maturity_t new_maturity
            cfunc = va_arg(va, cfunc_t*);
            extra = va_arg(va, int); // new_maturity
            break;
        }
        case hxe_interr: {
            // int errcode
            extra = va_arg(va, int);
            break;
        }
        case hxe_combine: {
            // mblock_t *blk, minsn_t *insn
            // For now, we don't extract these - just notify
            break;
        }
        case hxe_print_func:
        case hxe_func_printed: {
            // cfunc_t *cfunc
            cfunc = va_arg(va, cfunc_t*);
            break;
        }
        case hxe_structural: {
            // control_graph_t *ct
            // Skip - complex type
            break;
        }
        case hxe_build_callinfo: {
            // mblock_t *blk, tinfo_t *type, mcallinfo_t **callinfo
            // Skip - complex types
            break;
        }
        default:
            // Unknown or UI event - just pass event type
            break;
    }

    return idalib_hexrays_rust_event_handler(static_cast<int>(event), mba, cfunc, extra);
}

// Install the hexrays callback
inline bool idalib_hexrays_install_callback() {
    if (g_hexrays_callback_installed) {
        return true; // Already installed
    }
    g_hexrays_callback_installed = install_hexrays_callback(idalib_hexrays_trampoline_callback, nullptr);
    return g_hexrays_callback_installed;
}

// Remove the hexrays callback
inline void idalib_hexrays_remove_callback() {
    if (g_hexrays_callback_installed) {
        remove_hexrays_callback(idalib_hexrays_trampoline_callback, nullptr);
        g_hexrays_callback_installed = false;
    }
}

// Check if callback is installed
inline bool idalib_hexrays_has_callback() {
    return g_hexrays_callback_installed;
}

// ============================================================================
// Function Role Constants (funcrole_t)
// ============================================================================

inline int idalib_hexrays_role_unk() { return ROLE_UNK; }
inline int idalib_hexrays_role_empty() { return ROLE_EMPTY; }
inline int idalib_hexrays_role_memset() { return ROLE_MEMSET; }
inline int idalib_hexrays_role_memset32() { return ROLE_MEMSET32; }
inline int idalib_hexrays_role_memset64() { return ROLE_MEMSET64; }
inline int idalib_hexrays_role_memcpy() { return ROLE_MEMCPY; }
inline int idalib_hexrays_role_strcpy() { return ROLE_STRCPY; }
inline int idalib_hexrays_role_strlen() { return ROLE_STRLEN; }
inline int idalib_hexrays_role_strcat() { return ROLE_STRCAT; }
inline int idalib_hexrays_role_tail() { return ROLE_TAIL; }
inline int idalib_hexrays_role_bug() { return ROLE_BUG; }
inline int idalib_hexrays_role_alloca() { return ROLE_ALLOCA; }
inline int idalib_hexrays_role_bswap() { return ROLE_BSWAP; }
inline int idalib_hexrays_role_present() { return ROLE_PRESENT; }
inline int idalib_hexrays_role_containing_record() { return ROLE_CONTAINING_RECORD; }
inline int idalib_hexrays_role_fastfail() { return ROLE_FASTFAIL; }
inline int idalib_hexrays_role_readflags() { return ROLE_READFLAGS; }
inline int idalib_hexrays_role_is_mul_ok() { return ROLE_IS_MUL_OK; }
inline int idalib_hexrays_role_saturated_mul() { return ROLE_SATURATED_MUL; }
inline int idalib_hexrays_role_bittest() { return ROLE_BITTEST; }
inline int idalib_hexrays_role_bittestandset() { return ROLE_BITTESTANDSET; }
inline int idalib_hexrays_role_bittestandreset() { return ROLE_BITTESTANDRESET; }
inline int idalib_hexrays_role_bittestandcomplement() { return ROLE_BITTESTANDCOMPLEMENT; }
inline int idalib_hexrays_role_va_arg() { return ROLE_VA_ARG; }
inline int idalib_hexrays_role_va_copy() { return ROLE_VA_COPY; }
inline int idalib_hexrays_role_va_start() { return ROLE_VA_START; }
inline int idalib_hexrays_role_va_end() { return ROLE_VA_END; }
inline int idalib_hexrays_role_rol() { return ROLE_ROL; }
inline int idalib_hexrays_role_ror() { return ROLE_ROR; }
inline int idalib_hexrays_role_cfsub3() { return ROLE_CFSUB3; }
inline int idalib_hexrays_role_ofsub3() { return ROLE_OFSUB3; }
inline int idalib_hexrays_role_abs() { return ROLE_ABS; }
inline int idalib_hexrays_role_3waycmp0() { return ROLE_3WAYCMP0; }
inline int idalib_hexrays_role_3waycmp1() { return ROLE_3WAYCMP1; }
inline int idalib_hexrays_role_wmemcpy() { return ROLE_WMEMCPY; }
inline int idalib_hexrays_role_wmemset() { return ROLE_WMEMSET; }
inline int idalib_hexrays_role_wcscpy() { return ROLE_WCSCPY; }
inline int idalib_hexrays_role_wcslen() { return ROLE_WCSLEN; }
inline int idalib_hexrays_role_wcscat() { return ROLE_WCSCAT; }
inline int idalib_hexrays_role_sse_cmp4() { return ROLE_SSE_CMP4; }
inline int idalib_hexrays_role_sse_cmp8() { return ROLE_SSE_CMP8; }

// Get role name as string
inline rust::String idalib_hexrays_role_name(int role) {
  switch (role) {
    case ROLE_UNK: return rust::String("unknown");
    case ROLE_EMPTY: return rust::String("empty");
    case ROLE_MEMSET: return rust::String("memset");
    case ROLE_MEMSET32: return rust::String("memset32");
    case ROLE_MEMSET64: return rust::String("memset64");
    case ROLE_MEMCPY: return rust::String("memcpy");
    case ROLE_STRCPY: return rust::String("strcpy");
    case ROLE_STRLEN: return rust::String("strlen");
    case ROLE_STRCAT: return rust::String("strcat");
    case ROLE_TAIL: return rust::String("tail");
    case ROLE_BUG: return rust::String("bug");
    case ROLE_ALLOCA: return rust::String("alloca");
    case ROLE_BSWAP: return rust::String("bswap");
    case ROLE_PRESENT: return rust::String("present");
    case ROLE_CONTAINING_RECORD: return rust::String("containing_record");
    case ROLE_FASTFAIL: return rust::String("fastfail");
    case ROLE_READFLAGS: return rust::String("readflags");
    case ROLE_IS_MUL_OK: return rust::String("is_mul_ok");
    case ROLE_SATURATED_MUL: return rust::String("saturated_mul");
    case ROLE_BITTEST: return rust::String("bittest");
    case ROLE_BITTESTANDSET: return rust::String("bittestandset");
    case ROLE_BITTESTANDRESET: return rust::String("bittestandreset");
    case ROLE_BITTESTANDCOMPLEMENT: return rust::String("bittestandcomplement");
    case ROLE_VA_ARG: return rust::String("va_arg");
    case ROLE_VA_COPY: return rust::String("va_copy");
    case ROLE_VA_START: return rust::String("va_start");
    case ROLE_VA_END: return rust::String("va_end");
    case ROLE_ROL: return rust::String("rol");
    case ROLE_ROR: return rust::String("ror");
    case ROLE_CFSUB3: return rust::String("cfsub3");
    case ROLE_OFSUB3: return rust::String("ofsub3");
    case ROLE_ABS: return rust::String("abs");
    case ROLE_3WAYCMP0: return rust::String("3waycmp0");
    case ROLE_3WAYCMP1: return rust::String("3waycmp1");
    case ROLE_WMEMCPY: return rust::String("wmemcpy");
    case ROLE_WMEMSET: return rust::String("wmemset");
    case ROLE_WCSCPY: return rust::String("wcscpy");
    case ROLE_WCSLEN: return rust::String("wcslen");
    case ROLE_WCSCAT: return rust::String("wcscat");
    case ROLE_SSE_CMP4: return rust::String("sse_cmp4");
    case ROLE_SSE_CMP8: return rust::String("sse_cmp8");
    default: return rust::String("unknown");
  }
}

// ============================================================================
// Item Preciser Constants (for comment locations)
// ============================================================================

inline int idalib_hexrays_itp_empty() { return ITP_EMPTY; }
inline int idalib_hexrays_itp_arg1() { return ITP_ARG1; }
inline int idalib_hexrays_itp_arg64() { return ITP_ARG64; }
inline int idalib_hexrays_itp_brace1() { return ITP_BRACE1; }
inline int idalib_hexrays_itp_asm() { return ITP_ASM; }
inline int idalib_hexrays_itp_else() { return ITP_ELSE; }
inline int idalib_hexrays_itp_do() { return ITP_DO; }
inline int idalib_hexrays_itp_semi() { return ITP_SEMI; }
inline int idalib_hexrays_itp_curly1() { return ITP_CURLY1; }
inline int idalib_hexrays_itp_curly2() { return ITP_CURLY2; }
inline int idalib_hexrays_itp_brace2() { return ITP_BRACE2; }
inline int idalib_hexrays_itp_colon() { return ITP_COLON; }
inline int idalib_hexrays_itp_block1() { return ITP_BLOCK1; }
inline int idalib_hexrays_itp_block2() { return ITP_BLOCK2; }
inline int idalib_hexrays_itp_case() { return ITP_CASE; }
inline int idalib_hexrays_itp_sign() { return ITP_SIGN; }

// ============================================================================
// User Comments API
// ============================================================================

// Get user comment at a specific location (ea + item_preciser)
inline rust::String idalib_hexrays_cfunc_get_user_cmt(const cfunc_t *cfunc, ea_t ea, int itp) {
  if (!cfunc) return rust::String();
  treeloc_t loc;
  loc.ea = ea;
  loc.itp = static_cast<item_preciser_t>(itp);
  const char *cmt = cfunc->get_user_cmt(loc, RETRIEVE_ALWAYS);
  return cmt ? rust::String(cmt) : rust::String();
}

// Set user comment at a specific location
inline void idalib_hexrays_cfunc_set_user_cmt(cfunc_t *cfunc, ea_t ea, int itp, rust::Str cmt) {
  if (!cfunc) return;
  treeloc_t loc;
  loc.ea = ea;
  loc.itp = static_cast<item_preciser_t>(itp);
  std::string cmt_str(cmt.data(), cmt.size());
  cfunc->set_user_cmt(loc, cmt_str.empty() ? nullptr : cmt_str.c_str());
}

// Get number of user comments
inline size_t idalib_hexrays_cfunc_user_cmts_count(const cfunc_t *cfunc) {
  if (!cfunc || !cfunc->user_cmts) return 0;
  return cfunc->user_cmts->size();
}

// ============================================================================
// User Labels API
// ============================================================================

// Get user label at an address
inline rust::String idalib_hexrays_cfunc_get_user_label(const cfunc_t *cfunc, int label_num) {
  if (!cfunc || !cfunc->user_labels) return rust::String();
  for (auto it = cfunc->user_labels->begin(); it != cfunc->user_labels->end(); ++it) {
    if (it->first == label_num) {
      return rust::String(it->second.c_str());
    }
  }
  return rust::String();
}

// Set user label
inline void idalib_hexrays_cfunc_set_user_label(cfunc_t *cfunc, int label_num, rust::Str label) {
  if (!cfunc) return;
  if (!cfunc->user_labels) {
    // Need to create - but we can't easily create a new one via FFI
    // This would require save_user_labels/restore_user_labels
    return;
  }
  std::string label_str(label.data(), label.size());
  (*cfunc->user_labels)[label_num] = qstring(label_str.c_str());
}

// Get number of user labels
inline size_t idalib_hexrays_cfunc_user_labels_count(const cfunc_t *cfunc) {
  if (!cfunc || !cfunc->user_labels) return 0;
  return cfunc->user_labels->size();
}

// ============================================================================
// Number Format API
// ============================================================================

// Number format property bits
inline int idalib_hexrays_nf_fixed() { return NF_FIXED; }
inline int idalib_hexrays_nf_negate() { return NF_NEGATE; }
inline int idalib_hexrays_nf_bitnot() { return NF_BITNOT; }

// Get number of user-defined number formats
inline size_t idalib_hexrays_cfunc_numforms_count(const cfunc_t *cfunc) {
  if (!cfunc || !cfunc->numforms) return 0;
  return cfunc->numforms->size();
}

// ============================================================================
// CItem Tree Location Helpers
// ============================================================================

// Get the item preciser for argument N (for placing comments after call arguments)
inline int idalib_hexrays_itp_for_arg(int argnum) {
  if (argnum < 0 || argnum > 63) return ITP_EMPTY;
  return ITP_ARG1 + argnum;
}

// ============================================================================
// Local Variable Persistent Modification APIs
// ============================================================================

// MLI flags for modify_user_lvar_info
inline int idalib_hexrays_mli_name() { return MLI_NAME; }
inline int idalib_hexrays_mli_type() { return MLI_TYPE; }
inline int idalib_hexrays_mli_cmt() { return MLI_CMT; }
inline int idalib_hexrays_mli_set_flags() { return MLI_SET_FLAGS; }
inline int idalib_hexrays_mli_clr_flags() { return MLI_CLR_FLAGS; }

// LVINF flags for lvar_saved_info_t
inline int idalib_hexrays_lvinf_keep() { return LVINF_KEEP; }
inline int idalib_hexrays_lvinf_split() { return LVINF_SPLIT; }
inline int idalib_hexrays_lvinf_noptr() { return LVINF_NOPTR; }
inline int idalib_hexrays_lvinf_nomap() { return LVINF_NOMAP; }
inline int idalib_hexrays_lvinf_unused() { return LVINF_UNUSED; }

// Rename local variable persistently (saves to database)
// This uses modify_user_lvar_info with MLI_NAME flag
inline bool idalib_hexrays_lvar_rename_persistent(ea_t func_ea, lvar_t *v, rust::Str name) {
  if (!v) return false;
  
  lvar_saved_info_t info;
  info.ll = *static_cast<lvar_locator_t*>(v);  // Copy locator from lvar
  std::string name_str(name.data(), name.size());
  info.name = qstring(name_str.c_str());
  
  return modify_user_lvar_info(func_ea, MLI_NAME, info);
}

// Set local variable type persistently (saves to database)
// Type is specified as a C declaration string
inline bool idalib_hexrays_lvar_set_type_persistent(ea_t func_ea, lvar_t *v, rust::Str type_str) {
  if (!v) return false;
  
  std::string type_s(type_str.data(), type_str.size());
  
  tinfo_t tif;
  if (!parse_decl(&tif, nullptr, nullptr, type_s.c_str(), PT_VAR | PT_RAWARGS)) {
    return false;
  }
  
  lvar_saved_info_t info;
  info.ll = *static_cast<lvar_locator_t*>(v);
  info.type = tif;
  
  return modify_user_lvar_info(func_ea, MLI_TYPE, info);
}

// Set local variable comment persistently (saves to database)
inline bool idalib_hexrays_lvar_set_cmt_persistent(ea_t func_ea, lvar_t *v, rust::Str cmt) {
  if (!v) return false;
  
  lvar_saved_info_t info;
  info.ll = *static_cast<lvar_locator_t*>(v);
  std::string cmt_str(cmt.data(), cmt.size());
  info.cmt = qstring(cmt_str.c_str());
  
  return modify_user_lvar_info(func_ea, MLI_CMT, info);
}

// Set local variable as "no pointer" type (persistent)
inline bool idalib_hexrays_lvar_set_noptr(ea_t func_ea, lvar_t *v, bool noptr) {
  if (!v) return false;
  
  lvar_saved_info_t info;
  info.ll = *static_cast<lvar_locator_t*>(v);
  if (noptr) {
    info.flags |= LVINF_NOPTR;
  }
  
  return modify_user_lvar_info(func_ea, noptr ? MLI_SET_FLAGS : MLI_CLR_FLAGS, info);
}

// Set local variable as "no map" (forbid automatic mapping)
inline bool idalib_hexrays_lvar_set_nomap(ea_t func_ea, lvar_t *v, bool nomap) {
  if (!v) return false;
  
  lvar_saved_info_t info;
  info.ll = *static_cast<lvar_locator_t*>(v);
  if (nomap) {
    info.flags |= LVINF_NOMAP;
  }
  
  return modify_user_lvar_info(func_ea, nomap ? MLI_SET_FLAGS : MLI_CLR_FLAGS, info);
}

// Set local variable as unused argument
inline bool idalib_hexrays_lvar_set_unused(ea_t func_ea, lvar_t *v, bool unused) {
  if (!v) return false;
  
  lvar_saved_info_t info;
  info.ll = *static_cast<lvar_locator_t*>(v);
  if (unused) {
    info.flags |= LVINF_UNUSED;
  }
  
  return modify_user_lvar_info(func_ea, unused ? MLI_SET_FLAGS : MLI_CLR_FLAGS, info);
}

// Combined rename + retype + comment in one call (efficient for multiple changes)
inline bool idalib_hexrays_lvar_modify_persistent(
    ea_t func_ea, 
    lvar_t *v,
    rust::Str name,       // empty = don't change
    rust::Str type_str,   // empty = don't change
    rust::Str cmt         // empty = don't change
) {
  if (!v) return false;
  
  lvar_saved_info_t info;
  info.ll = *static_cast<lvar_locator_t*>(v);
  
  uint mli_flags = 0;
  
  if (!name.empty()) {
    std::string name_s(name.data(), name.size());
    info.name = qstring(name_s.c_str());
    mli_flags |= MLI_NAME;
  }
  
  if (!type_str.empty()) {
    std::string type_s(type_str.data(), type_str.size());
    tinfo_t tif;
    if (parse_decl(&tif, nullptr, nullptr, type_s.c_str(), PT_VAR | PT_RAWARGS)) {
      info.type = tif;
      mli_flags |= MLI_TYPE;
    }
  }
  
  if (!cmt.empty()) {
    std::string cmt_s(cmt.data(), cmt.size());
    info.cmt = qstring(cmt_s.c_str());
    mli_flags |= MLI_CMT;
  }
  
  if (mli_flags == 0) return true;  // Nothing to do
  
  return modify_user_lvar_info(func_ea, mli_flags, info);
}

// Get the function entry EA from a cfunc (needed for persistent modifications)
inline ea_t idalib_hexrays_cfunc_entry_for_lvar(const cfunc_t *f) {
  return f ? f->entry_ea : BADADDR;
}
