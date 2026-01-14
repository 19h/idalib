#pragma once

#include "nalt.hpp"
#include "pro.h"

#include "cxx.h"

rust::String idalib_get_input_file_path() {
  char path[QMAXPATH] = {0};
  auto size = get_input_file_path(path, sizeof(path));

  if (size > 0) {
    return rust::String(path, size);
  } else {
    return rust::String();
  }
}

// Get root filename
inline rust::String idalib_get_root_filename() {
    char buf[QMAXPATH] = {0};
    if (get_root_filename(buf, sizeof(buf)) > 0) {
        return rust::String(buf);
    }
    return rust::String();
}

// Get debug input path
inline rust::String idalib_dbg_get_input_path() {
    char buf[QMAXPATH] = {0};
    if (dbg_get_input_path(buf, sizeof(buf)) > 0) {
        return rust::String(buf);
    }
    return rust::String();
}

// Get string type at address
inline uint32_t idalib_get_str_type(ea_t ea) {
    return get_str_type(ea);
}

// Set string type at address
inline void idalib_set_str_type(ea_t ea, uint32_t strtype) {
    set_str_type(ea, strtype);
}

// Delete string type at address
inline void idalib_del_str_type(ea_t ea) {
    del_str_type(ea);
}

// Get item color
inline uint32_t idalib_get_item_color(ea_t ea) {
    return get_item_color(ea);
}

// Set item color
inline void idalib_set_item_color(ea_t ea, uint32_t color) {
    set_item_color(ea, color);
}

// Delete item color
inline bool idalib_del_item_color(ea_t ea) {
    return del_item_color(ea);
}

// Get source line number
inline uint64_t idalib_get_source_linnum(ea_t ea) {
    return get_source_linnum(ea);
}

// Set source line number
inline void idalib_set_source_linnum(ea_t ea, uint64_t lnnum) {
    set_source_linnum(ea, lnnum);
}

// Delete source line number
inline void idalib_del_source_linnum(ea_t ea) {
    del_source_linnum(ea);
}

// Get aflags (additional flags)
inline uint32_t idalib_get_aflags(ea_t ea) {
    return get_aflags(ea);
}

// Set aflags
inline void idalib_set_aflags(ea_t ea, uint32_t flags) {
    set_aflags(ea, flags);
}

// Set abits (set bits in aflags)
inline void idalib_set_abits(ea_t ea, uint32_t bits) {
    set_abits(ea, bits);
}

// Clear abits
inline void idalib_clr_abits(ea_t ea, uint32_t bits) {
    clr_abits(ea, bits);
}

// Delete aflags
inline void idalib_del_aflags(ea_t ea) {
    del_aflags(ea);
}

// Get import module count
inline uint32_t idalib_get_import_module_qty() {
    return get_import_module_qty();
}

// Get import module name
inline rust::String idalib_get_import_module_name(int mod_index) {
    qstring buf;
    if (get_import_module_name(&buf, mod_index)) {
        return rust::String(buf.c_str());
    }
    return rust::String();
}

// Get encoding count
inline int idalib_get_encoding_qty() {
    return get_encoding_qty();
}

// Get encoding name
inline rust::String idalib_get_encoding_name(int idx) {
    const char *name = get_encoding_name(idx);
    return name ? rust::String(name) : rust::String();
}

// Add encoding
inline int idalib_add_encoding(const char *encname) {
    return add_encoding(encname);
}

// Delete encoding
inline bool idalib_del_encoding(int idx) {
    return del_encoding(idx);
}

// Get encoding bytes per unit
inline int idalib_get_encoding_bpu(int idx) {
    return get_encoding_bpu(idx);
}

// Check if there's switch info at address
inline bool idalib_has_switch_info(ea_t ea) {
    switch_info_t si;
    return get_switch_info(&si, ea) > 0;
}

// Get switch info jump table address
inline ea_t idalib_get_switch_jumps(ea_t ea) {
    switch_info_t si;
    if (get_switch_info(&si, ea) > 0) {
        return si.jumps;
    }
    return BADADDR;
}

// Get switch info number of cases
inline int idalib_get_switch_ncases(ea_t ea) {
    switch_info_t si;
    if (get_switch_info(&si, ea) > 0) {
        return si.ncases;
    }
    return 0;
}

// Get switch info low case
inline int64_t idalib_get_switch_lowcase(ea_t ea) {
    switch_info_t si;
    if (get_switch_info(&si, ea) > 0) {
        return si.lowcase;
    }
    return 0;
}

// Delete switch info
inline void idalib_del_switch_info(ea_t ea) {
    del_switch_info(ea);
}

// Get tinfo at address (returns true if found)
inline bool idalib_has_tinfo(ea_t ea) {
    tinfo_t tif;
    return get_tinfo(&tif, ea);
}

// Delete tinfo at address
inline bool idalib_del_tinfo(ea_t ea) {
    return set_tinfo(ea, nullptr);
}

// Get operand tinfo (returns true if found)
inline bool idalib_has_op_tinfo(ea_t ea, int n) {
    tinfo_t tif;
    return get_op_tinfo(&tif, ea, n);
}
