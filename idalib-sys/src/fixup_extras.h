#pragma once

#include "fixup.hpp"

#include "cxx.h"

// Check if fixup exists
bool idalib_exists_fixup(ea_t source) {
  return exists_fixup(source);
}

// Get fixup information
bool idalib_get_fixup(ea_t source, uint16_t *type, uint32_t *flags, ea_t *sel, ea_t *off, int64_t *displacement) {
  fixup_data_t fd;
  if (get_fixup(&fd, source)) {
    *type = fd.get_type();
    *flags = fd.get_flags();
    *sel = fd.sel;
    *off = fd.off;
    *displacement = static_cast<int64_t>(fd.displacement);
    return true;
  }
  return false;
}

// Set fixup information
void idalib_set_fixup(ea_t source, uint16_t type, uint32_t flags, ea_t sel, ea_t off, int64_t displacement) {
  fixup_data_t fd(static_cast<fixup_type_t>(type), flags);
  fd.sel = sel;
  fd.off = off;
  fd.displacement = static_cast<adiff_t>(displacement);
  set_fixup(source, fd);
}

// Delete fixup
void idalib_del_fixup(ea_t source) {
  del_fixup(source);
}

// Enumerate fixups
ea_t idalib_get_first_fixup_ea() {
  return get_first_fixup_ea();
}

ea_t idalib_get_next_fixup_ea(ea_t ea) {
  return get_next_fixup_ea(ea);
}

ea_t idalib_get_prev_fixup_ea(ea_t ea) {
  return get_prev_fixup_ea(ea);
}

// Check for fixups in range
bool idalib_contains_fixups(ea_t ea, uint64_t size) {
  return contains_fixups(ea, static_cast<asize_t>(size));
}

// Apply fixup
bool idalib_apply_fixup(ea_t item_ea, ea_t fixup_ea, int n, bool is_macro) {
  return apply_fixup(item_ea, fixup_ea, n, is_macro);
}

// Get fixup value
uint64_t idalib_get_fixup_value(ea_t ea, uint16_t type) {
  return static_cast<uint64_t>(get_fixup_value(ea, static_cast<fixup_type_t>(type)));
}

// Calculate fixup size
int idalib_calc_fixup_size(uint16_t type) {
  return calc_fixup_size(static_cast<fixup_type_t>(type));
}

// Fixup description
rust::String idalib_get_fixup_desc(ea_t source) {
  fixup_data_t fd;
  if (get_fixup(&fd, source)) {
    auto buf = qstring();
    get_fixup_desc(&buf, source, fd);
    return rust::String(buf.c_str());
  }
  return rust::String();
}

// Is custom fixup
bool idalib_is_fixup_custom(uint16_t type) {
  return is_fixup_custom(static_cast<fixup_type_t>(type));
}
