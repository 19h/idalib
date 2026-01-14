#pragma once

#include "auto.hpp"

#include "cxx.h"

// Auto state
int idalib_get_auto_state() {
  return static_cast<int>(get_auto_state());
}

int idalib_set_auto_state(int new_state) {
  return static_cast<int>(set_auto_state(static_cast<atype_t>(new_state)));
}

// IDA state
int idalib_set_ida_state(int st) {
  return static_cast<int>(set_ida_state(static_cast<idastate_t>(st)));
}

// Auto mark
void idalib_auto_mark(ea_t ea, int type) {
  auto_mark(ea, static_cast<atype_t>(type));
}

void idalib_auto_mark_range(ea_t start, ea_t end, int type) {
  auto_mark_range(start, end, static_cast<atype_t>(type));
}

void idalib_auto_unmark(ea_t start, ea_t end, int type) {
  auto_unmark(start, end, static_cast<atype_t>(type));
}

// Convenience functions
void idalib_plan_ea(ea_t ea) {
  plan_ea(ea);
}

void idalib_plan_range(ea_t sEA, ea_t eEA) {
  plan_range(sEA, eEA);
}

void idalib_auto_make_code(ea_t ea) {
  auto_make_code(ea);
}

void idalib_auto_make_proc(ea_t ea) {
  auto_make_proc(ea);
}

// Auto analysis control
bool idalib_auto_is_ok() {
  return auto_is_ok();
}

void idalib_auto_cancel(ea_t ea1, ea_t ea2) {
  auto_cancel(ea1, ea2);
}

int idalib_plan_and_wait(ea_t ea1, ea_t ea2, bool final_pass) {
  return plan_and_wait(ea1, ea2, final_pass);
}

int64_t idalib_auto_wait_range(ea_t ea1, ea_t ea2) {
  return static_cast<int64_t>(auto_wait_range(ea1, ea2));
}

bool idalib_auto_make_step(ea_t ea1, ea_t ea2) {
  return auto_make_step(ea1, ea2);
}

// Peek into queue
ea_t idalib_peek_auto_queue(ea_t low_ea, int type) {
  return peek_auto_queue(low_ea, static_cast<atype_t>(type));
}

// Enable/disable
bool idalib_is_auto_enabled() {
  return is_auto_enabled();
}

bool idalib_enable_auto(bool enable) {
  return enable_auto(enable);
}

// Reanalyze callers
void idalib_reanalyze_callers(ea_t ea, bool noret) {
  reanalyze_callers(ea, noret);
}

// Revert IDA decisions
void idalib_revert_ida_decisions(ea_t ea1, ea_t ea2) {
  revert_ida_decisions(ea1, ea2);
}

// Auto apply type
void idalib_auto_apply_type(ea_t caller, ea_t callee) {
  auto_apply_type(caller, callee);
}

// Auto recreate instruction
int idalib_auto_recreate_insn(ea_t ea) {
  return auto_recreate_insn(ea);
}

// May trace SP
bool idalib_may_trace_sp() {
  return may_trace_sp();
}

// May create stack vars
bool idalib_may_create_stkvars() {
  return may_create_stkvars();
}
