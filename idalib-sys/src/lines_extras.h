#pragma once

#include "lines.hpp"

#include "cxx.h"

// Generate disassembly line
rust::String idalib_generate_disasm_line(ea_t ea, int flags) {
  auto buf = qstring();
  if (generate_disasm_line(&buf, ea, flags)) {
    return rust::String(buf.c_str());
  }
  return rust::String();
}

// Generate disassembly without color tags
rust::String idalib_generate_disasm_line_no_tags(ea_t ea) {
  auto buf = qstring();
  if (generate_disasm_line(&buf, ea, GENDSM_REMOVE_TAGS)) {
    return rust::String(buf.c_str());
  }
  return rust::String();
}

// Generate multiple disassembly lines
int idalib_generate_disassembly(ea_t ea, int maxlines, rust::Vec<rust::String> &out) {
  qstrvec_t lines;
  int lnnum = 0;
  int count = generate_disassembly(&lines, &lnnum, ea, maxlines, 0);
  for (const auto &line : lines) {
    out.push_back(rust::String(line.c_str()));
  }
  return count;
}

// Tag functions
rust::String idalib_tag_remove(const char *line) {
  auto buf = qstring();
  if (tag_remove(&buf, line) >= 0) {
    return rust::String(buf.c_str());
  }
  return rust::String();
}

int64_t idalib_tag_strlen(const char *line) {
  return static_cast<int64_t>(tag_strlen(line));
}

// Extra lines (anterior/posterior)
bool idalib_add_extra_line(ea_t ea, bool isprev, const char *line) {
  return add_extra_line(ea, isprev, "%s", line);
}

bool idalib_add_extra_cmt(ea_t ea, bool isprev, const char *cmt) {
  return add_extra_cmt(ea, isprev, "%s", cmt);
}

bool idalib_add_pgm_cmt(const char *cmt) {
  return add_pgm_cmt("%s", cmt);
}

// Get extra comment
rust::String idalib_get_extra_cmt(ea_t ea, int n) {
  auto buf = qstring();
  if (get_extra_cmt(&buf, ea, n) > 0) {
    return rust::String(buf.c_str());
  }
  return rust::String();
}

// Delete extra comments
bool idalib_del_extra_cmt(ea_t ea, int n) {
  return del_extra_cmt(ea, n);
}

void idalib_delete_extra_cmts(ea_t ea, int n) {
  delete_extra_cmts(ea, n);
}

// Source file operations
bool idalib_add_sourcefile(ea_t ea1, ea_t ea2, const char *filename) {
  return add_sourcefile(ea1, ea2, filename);
}

rust::String idalib_get_sourcefile(ea_t ea) {
  const char *name = get_sourcefile(ea);
  if (name != nullptr) {
    return rust::String(name);
  }
  return rust::String();
}

bool idalib_del_sourcefile(ea_t ea) {
  return del_sourcefile(ea);
}

// Prefix color
uint8_t idalib_calc_prefix_color(ea_t ea) {
  return static_cast<uint8_t>(calc_prefix_color(ea));
}

// Background color
uint32_t idalib_calc_bg_color(ea_t ea) {
  return static_cast<uint32_t>(calc_bg_color(ea));
}
