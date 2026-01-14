#pragma once

#include "bytes.hpp"

#include "cxx.h"

// Reading bytes
std::uint8_t idalib_get_byte(ea_t ea) { return get_byte(ea); }
std::uint16_t idalib_get_word(ea_t ea) { return get_word(ea); }
std::uint32_t idalib_get_dword(ea_t ea) { return get_dword(ea); }
std::uint64_t idalib_get_qword(ea_t ea) { return get_qword(ea); }

std::size_t idalib_get_bytes(ea_t ea, rust::Vec<rust::u8> &buf) {
  if (auto sz = get_bytes(buf.data(), buf.capacity(), ea, GMB_READALL);
      sz >= 0) {
    return sz;
  } else {
    return 0;
  }
}

// Patching bytes
bool idalib_patch_byte(ea_t ea, uint8_t value) {
  return patch_byte(ea, value);
}

bool idalib_patch_word(ea_t ea, uint16_t value) {
  return patch_word(ea, static_cast<uint64>(value));
}

bool idalib_patch_dword(ea_t ea, uint32_t value) {
  return patch_dword(ea, static_cast<uint64>(value));
}

bool idalib_patch_qword(ea_t ea, uint64_t value) {
  return patch_qword(ea, static_cast<uint64>(value));
}

void idalib_patch_bytes(ea_t ea, const rust::Slice<const uint8_t> data) {
  patch_bytes(ea, data.data(), data.size());
}

// Original bytes (before patching)
uint8_t idalib_get_original_byte(ea_t ea) {
  return static_cast<uint8_t>(get_original_byte(ea));
}

uint16_t idalib_get_original_word(ea_t ea) {
  return static_cast<uint16_t>(get_original_word(ea));
}

uint32_t idalib_get_original_dword(ea_t ea) {
  return static_cast<uint32_t>(get_original_dword(ea));
}

uint64_t idalib_get_original_qword(ea_t ea) {
  return static_cast<uint64_t>(get_original_qword(ea));
}

// Revert patches
void idalib_revert_byte(ea_t ea) {
  revert_byte(ea);
}

// Put bytes (modifies database, not patching)
bool idalib_put_byte(ea_t ea, uint8_t value) {
  return put_byte(ea, value);
}

void idalib_put_word(ea_t ea, uint16_t value) {
  put_word(ea, value);
}

void idalib_put_dword(ea_t ea, uint32_t value) {
  put_dword(ea, value);
}

void idalib_put_qword(ea_t ea, uint64_t value) {
  put_qword(ea, value);
}

void idalib_put_bytes(ea_t ea, const rust::Slice<const uint8_t> data) {
  put_bytes(ea, data.data(), data.size());
}

// Delete bytes
bool idalib_del_items(ea_t ea, int flags, uint64_t nbytes) {
  return del_items(ea, flags, static_cast<asize_t>(nbytes));
}

// Create data types
bool idalib_create_byte(ea_t ea, uint64_t length) {
  return create_byte(ea, static_cast<asize_t>(length));
}

bool idalib_create_word(ea_t ea, uint64_t length) {
  return create_word(ea, static_cast<asize_t>(length));
}

bool idalib_create_dword(ea_t ea, uint64_t length) {
  return create_dword(ea, static_cast<asize_t>(length));
}

bool idalib_create_qword(ea_t ea, uint64_t length) {
  return create_qword(ea, static_cast<asize_t>(length));
}

bool idalib_create_float(ea_t ea, uint64_t length) {
  return create_float(ea, static_cast<asize_t>(length));
}

bool idalib_create_double(ea_t ea, uint64_t length) {
  return create_double(ea, static_cast<asize_t>(length));
}

// Flags inspection
bool idalib_is_mapped(ea_t ea) {
  return is_mapped(ea);
}

bool idalib_is_loaded(ea_t ea) {
  return is_loaded(ea);
}

bool idalib_has_value(uint64_t flags) {
  return has_value(static_cast<flags64_t>(flags));
}

bool idalib_is_byte(uint64_t flags) {
  return is_byte(static_cast<flags64_t>(flags));
}

bool idalib_is_word(uint64_t flags) {
  return is_word(static_cast<flags64_t>(flags));
}

bool idalib_is_dword(uint64_t flags) {
  return is_dword(static_cast<flags64_t>(flags));
}

bool idalib_is_qword(uint64_t flags) {
  return is_qword(static_cast<flags64_t>(flags));
}

bool idalib_is_float(uint64_t flags) {
  return is_float(static_cast<flags64_t>(flags));
}

bool idalib_is_double(uint64_t flags) {
  return is_double(static_cast<flags64_t>(flags));
}

bool idalib_is_head(uint64_t flags) {
  return is_head(static_cast<flags64_t>(flags));
}

bool idalib_is_tail(uint64_t flags) {
  return is_tail(static_cast<flags64_t>(flags));
}

bool idalib_is_unknown(uint64_t flags) {
  return is_unknown(static_cast<flags64_t>(flags));
}

bool idalib_is_flow(uint64_t flags) {
  return is_flow(static_cast<flags64_t>(flags));
}

// Item size
uint64_t idalib_get_item_size(ea_t ea) {
  return static_cast<uint64_t>(get_item_size(ea));
}

ea_t idalib_get_item_end(ea_t ea) {
  return get_item_end(ea);
}

ea_t idalib_get_item_head(ea_t ea) {
  return get_item_head(ea);
}

// Next/prev
ea_t idalib_next_addr(ea_t ea) {
  return next_addr(ea);
}

ea_t idalib_prev_addr(ea_t ea) {
  return prev_addr(ea);
}

ea_t idalib_next_not_tail(ea_t ea) {
  return next_not_tail(ea);
}

ea_t idalib_prev_not_tail(ea_t ea) {
  return prev_not_tail(ea);
}

ea_t idalib_next_unknown(ea_t ea, ea_t maxea) {
  return next_unknown(ea, maxea);
}

ea_t idalib_prev_unknown(ea_t ea, ea_t minea) {
  return prev_unknown(ea, minea);
}

// Visit
ea_t idalib_next_that(ea_t ea, ea_t maxea, bool code) {
  if (code) {
    return next_that(ea, maxea, [](flags64_t f, void*) { return is_code(f); }, nullptr);
  } else {
    return next_that(ea, maxea, [](flags64_t f, void*) { return is_data(f); }, nullptr);
  }
}

ea_t idalib_prev_that(ea_t ea, ea_t minea, bool code) {
  if (code) {
    return prev_that(ea, minea, [](flags64_t f, void*) { return is_code(f); }, nullptr);
  } else {
    return prev_that(ea, minea, [](flags64_t f, void*) { return is_data(f); }, nullptr);
  }
}
