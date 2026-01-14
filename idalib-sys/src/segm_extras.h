#pragma once

#include "pro.h"
#include "bytes.hpp"
#include "segment.hpp"

#include <cstdint>
#include <exception>
#include <memory>

#include "cxx.h"

rust::String idalib_segm_name(const segment_t *s) {
  auto name = qstring();

  if (get_segm_name(&name, s) > 0) {
    return rust::String(name.c_str());
  } else {
    return rust::String();
  }
}

std::size_t idalib_segm_bytes(const segment_t *s, rust::Vec<rust::u8>& buf) {
  if (auto sz = get_bytes(buf.data(), buf.capacity(), s->start_ea, GMB_READALL); sz >= 0) {
    return sz;
  } else {
    return 0;
  }
}

std::uint8_t idalib_segm_align(const segment_t *s) {
  return s->align;
}

std::uint8_t idalib_segm_bitness(const segment_t *s) {
  return s->bitness;
}

std::uint8_t idalib_segm_perm(const segment_t *s) {
  return s->perm;
}

std::uint8_t idalib_segm_type(const segment_t *s) {
  return s->type;
}

// Segment manipulation functions

// Add a segment
inline bool idalib_add_segm(ea_t para, ea_t start, ea_t end, const char *name, const char *sclass) {
    return add_segm(para, start, end, name, sclass);
}

// Delete a segment
inline bool idalib_del_segm(ea_t ea, int flags) {
    return del_segm(ea, flags);
}

// Set segment start
inline bool idalib_set_segm_start(ea_t ea, ea_t newstart, int flags) {
    return set_segm_start(ea, newstart, flags);
}

// Set segment end
inline bool idalib_set_segm_end(ea_t ea, ea_t newend, int flags) {
    return set_segm_end(ea, newend, flags);
}

// Move segment start
inline bool idalib_move_segm_start(ea_t ea, ea_t newstart, int mode) {
    return move_segm_start(ea, newstart, mode);
}

// Set segment base
inline bool idalib_set_segm_base(segment_t *s, ea_t newbase) {
    return set_segm_base(s, newbase);
}

// Get segment number
inline int idalib_get_segm_num(ea_t ea) {
    return get_segm_num(ea);
}

// Get next segment
inline segment_t *idalib_get_next_seg(ea_t ea) {
    return get_next_seg(ea);
}

// Get previous segment
inline segment_t *idalib_get_prev_seg(ea_t ea) {
    return get_prev_seg(ea);
}

// Get first segment
inline segment_t *idalib_get_first_seg() {
    return get_first_seg();
}

// Get last segment
inline segment_t *idalib_get_last_seg() {
    return get_last_seg();
}

// Set segment visibility
inline void idalib_set_visible_segm(segment_t *s, bool visible) {
    set_visible_segm(s, visible);
}

// Check if segment is visible
inline bool idalib_is_visible_segm(segment_t *s) {
    return is_visible_segm(s);
}

// Check if special segment
inline bool idalib_is_spec_segm(uint8_t seg_type) {
    return is_spec_segm(seg_type);
}

// Check if address is in special segment
inline bool idalib_is_spec_ea(ea_t ea) {
    return is_spec_ea(ea);
}

// Lock segment
inline void idalib_lock_segm(const segment_t *segm, bool lock) {
    lock_segm(segm, lock);
}

// Check if segment is locked
inline bool idalib_is_segm_locked(const segment_t *segm) {
    return is_segm_locked(segm);
}

// Move segment to new address
inline int idalib_move_segm(segment_t *s, ea_t to, int flags) {
    return (int)move_segm(s, to, flags);
}

// Rebase program
inline int idalib_rebase_program(int64_t delta, int flags) {
    return (int)rebase_program(delta, flags);
}

// Get segment class
inline rust::String idalib_get_segm_class(const segment_t *s) {
    qstring name;
    if (get_segm_class(&name, s) > 0) {
        return rust::String(name.c_str());
    }
    return rust::String();
}

// Set segment class
inline int idalib_set_segm_class(segment_t *s, const char *sclass) {
    return set_segm_class(s, sclass);
}

// Change segment status (debug/non-debug)
inline int idalib_change_segment_status(segment_t *s, bool is_deb_segm) {
    return change_segment_status(s, is_deb_segm);
}

// Take memory snapshot
inline bool idalib_take_memory_snapshot(int type) {
    return take_memory_snapshot(type);
}

// Check if mini idb
inline bool idalib_is_miniidb() {
    return is_miniidb();
}

// Setup selector
inline uint64_t idalib_setup_selector(ea_t segbase) {
    return setup_selector(segbase);
}

// Allocate selector
inline uint64_t idalib_allocate_selector(ea_t segbase) {
    return allocate_selector(segbase);
}

// Find free selector
inline uint64_t idalib_find_free_selector() {
    return find_free_selector();
}

// Delete selector
inline void idalib_del_selector(uint64_t selector) {
    del_selector(selector);
}

// Get selector count
inline size_t idalib_get_selector_qty() {
    return get_selector_qty();
}

// Selector to paragraph
inline ea_t idalib_sel2para(uint64_t selector) {
    return sel2para(selector);
}

// Find selector by base
inline uint64_t idalib_find_selector(ea_t base) {
    return find_selector(base);
}
