#pragma once

#include "name.hpp"
#include "demangle.hpp"

#include "cxx.h"

// Name setting
bool idalib_set_name(ea_t ea, const char *name, int flags) {
  return set_name(ea, name, flags);
}

bool idalib_del_name(ea_t ea) {
  return set_name(ea, "", SN_NOWARN);
}

bool idalib_force_name(ea_t ea, const char *name, int flags) {
  return force_name(ea, name, flags);
}

// Name getting
rust::String idalib_get_name(ea_t ea) {
  auto name = qstring();
  if (get_name(&name, ea) > 0) {
    return rust::String(name.c_str());
  }
  return rust::String();
}

rust::String idalib_get_visible_name(ea_t ea) {
  auto name = qstring();
  if (get_visible_name(&name, ea) > 0) {
    return rust::String(name.c_str());
  }
  return rust::String();
}

rust::String idalib_get_short_name(ea_t ea) {
  auto name = qstring();
  if (get_short_name(&name, ea) > 0) {
    return rust::String(name.c_str());
  }
  return rust::String();
}

rust::String idalib_get_long_name(ea_t ea) {
  auto name = qstring();
  if (get_long_name(&name, ea) > 0) {
    return rust::String(name.c_str());
  }
  return rust::String();
}

rust::String idalib_get_colored_name(ea_t ea) {
  auto name = qstring();
  if (get_colored_name(&name, ea) > 0) {
    return rust::String(name.c_str());
  }
  return rust::String();
}

// Address lookup
ea_t idalib_get_name_ea(ea_t from, const char *name) {
  return get_name_ea(from, name);
}

// Demangling
rust::String idalib_demangle_name(const char *name, uint32_t disable_mask) {
  auto out = qstring();
  if (demangle_name(&out, name, disable_mask) > 0) {
    return rust::String(out.c_str());
  }
  return rust::String();
}

// Name validation
bool idalib_is_ident(const char *name) {
  return is_ident(name);
}

bool idalib_is_uname(const char *name) {
  return is_uname(name);
}

bool idalib_is_valid_typename(const char *name) {
  return is_valid_typename(name);
}

// Public/weak names
void idalib_make_name_public(ea_t ea) {
  make_name_public(ea);
}

void idalib_make_name_non_public(ea_t ea) {
  make_name_non_public(ea);
}

void idalib_make_name_weak(ea_t ea) {
  make_name_weak(ea);
}

void idalib_make_name_non_weak(ea_t ea) {
  make_name_non_weak(ea);
}

// Dummy name
ea_t idalib_dummy_name_ea(const char *name) {
  return dummy_name_ea(name);
}

bool idalib_set_dummy_name(ea_t from, ea_t ea) {
  return set_dummy_name(from, ea);
}

// User/auto names
bool idalib_make_name_auto(ea_t ea) {
  return make_name_auto(ea);
}

bool idalib_make_name_user(ea_t ea) {
  return make_name_user(ea);
}

// Hide/show names
void idalib_hide_name(ea_t ea) {
  hide_name(ea);
}

void idalib_show_name(ea_t ea) {
  show_name(ea);
}

// Rebuild name list
void idalib_rebuild_nlist() {
  rebuild_nlist();
}

// Clean name
rust::String idalib_cleanup_name(ea_t ea, const char *name, uint32_t flags) {
  auto out = qstring();
  if (cleanup_name(&out, ea, name, flags)) {
    return rust::String(out.c_str());
  }
  return rust::String();
}
