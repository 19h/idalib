#pragma once

#include "frame.hpp"
#include "funcs.hpp"

#include "cxx.h"

// Frame manipulation
bool idalib_add_frame(func_t *pfn, int64_t frsize, uint16_t frregs, uint64_t argsize) {
  return add_frame(pfn, static_cast<sval_t>(frsize), static_cast<ushort>(frregs), static_cast<asize_t>(argsize));
}

bool idalib_del_frame(func_t *pfn) {
  return del_frame(pfn);
}

bool idalib_set_frame_size(func_t *pfn, uint64_t frsize, uint16_t frregs, uint64_t argsize) {
  return set_frame_size(pfn, static_cast<asize_t>(frsize), static_cast<ushort>(frregs), static_cast<asize_t>(argsize));
}

uint64_t idalib_get_frame_size(const func_t *pfn) {
  return static_cast<uint64_t>(get_frame_size(pfn));
}

int idalib_get_frame_retsize(const func_t *pfn) {
  return get_frame_retsize(pfn);
}

// Frame part offsets
ea_t idalib_frame_off_args(const func_t *pfn) {
  return frame_off_args(pfn);
}

ea_t idalib_frame_off_retaddr(const func_t *pfn) {
  return frame_off_retaddr(pfn);
}

ea_t idalib_frame_off_savregs(const func_t *pfn) {
  return frame_off_savregs(pfn);
}

ea_t idalib_frame_off_lvars(const func_t *pfn) {
  return frame_off_lvars(pfn);
}

// Frame part ranges
void idalib_get_frame_part_args(const func_t *pfn, ea_t *start, ea_t *end) {
  range_t range;
  get_frame_part(&range, pfn, FPC_ARGS);
  *start = range.start_ea;
  *end = range.end_ea;
}

void idalib_get_frame_part_retaddr(const func_t *pfn, ea_t *start, ea_t *end) {
  range_t range;
  get_frame_part(&range, pfn, FPC_RETADDR);
  *start = range.start_ea;
  *end = range.end_ea;
}

void idalib_get_frame_part_savregs(const func_t *pfn, ea_t *start, ea_t *end) {
  range_t range;
  get_frame_part(&range, pfn, FPC_SAVREGS);
  *start = range.start_ea;
  *end = range.end_ea;
}

void idalib_get_frame_part_lvars(const func_t *pfn, ea_t *start, ea_t *end) {
  range_t range;
  get_frame_part(&range, pfn, FPC_LVARS);
  *start = range.start_ea;
  *end = range.end_ea;
}

// FPD update
bool idalib_update_fpd(func_t *pfn, uint64_t fpd) {
  return update_fpd(pfn, static_cast<asize_t>(fpd));
}

// Purged bytes
bool idalib_set_purged(ea_t ea, int nbytes, bool override_old_value) {
  return set_purged(ea, nbytes, override_old_value);
}

// SP change points
bool idalib_add_auto_stkpnt(func_t *pfn, ea_t ea, int64_t delta) {
  return add_auto_stkpnt(pfn, ea, static_cast<sval_t>(delta));
}

bool idalib_add_user_stkpnt(ea_t ea, int64_t delta) {
  return add_user_stkpnt(ea, static_cast<sval_t>(delta));
}

bool idalib_del_stkpnt(func_t *pfn, ea_t ea) {
  return del_stkpnt(pfn, ea);
}

int64_t idalib_get_spd(func_t *pfn, ea_t ea) {
  return static_cast<int64_t>(get_spd(pfn, ea));
}

int64_t idalib_get_effective_spd(func_t *pfn, ea_t ea) {
  return static_cast<int64_t>(get_effective_spd(pfn, ea));
}

int64_t idalib_get_sp_delta(func_t *pfn, ea_t ea) {
  return static_cast<int64_t>(get_sp_delta(pfn, ea));
}

bool idalib_set_auto_spd(func_t *pfn, ea_t ea, int64_t new_spd) {
  return set_auto_spd(pfn, ea, static_cast<sval_t>(new_spd));
}

// Build stack variable name
rust::String idalib_build_stkvar_name(const func_t *pfn, int64_t v) {
  auto buf = qstring();
  if (build_stkvar_name(&buf, pfn, static_cast<sval_t>(v)) > 0) {
    return rust::String(buf.c_str());
  }
  return rust::String();
}

// Register variables
bool idalib_has_regvar(func_t *pfn, ea_t ea) {
  return has_regvar(pfn, ea);
}

int idalib_add_regvar(func_t *pfn, ea_t ea1, ea_t ea2, const char *canon, const char *user, const char *cmt) {
  return add_regvar(pfn, ea1, ea2, canon, user, cmt);
}

int idalib_del_regvar(func_t *pfn, ea_t ea1, ea_t ea2, const char *canon) {
  return del_regvar(pfn, ea1, ea2, canon);
}

// Function frame info from func_t
int64_t idalib_func_frsize(const func_t *pfn) {
  return pfn ? static_cast<int64_t>(pfn->frsize) : 0;
}

uint16_t idalib_func_frregs(const func_t *pfn) {
  return pfn ? pfn->frregs : 0;
}

int64_t idalib_func_fpd(const func_t *pfn) {
  return pfn ? static_cast<int64_t>(pfn->fpd) : 0;
}

uint64_t idalib_func_argsize(const func_t *pfn) {
  return pfn ? static_cast<uint64_t>(pfn->argsize) : 0;
}
