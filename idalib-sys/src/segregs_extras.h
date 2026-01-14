#pragma once

#include "segregs.hpp"

#include "cxx.h"

// Segment register manipulation functions

// Get segment register value at an address
inline uint64_t idalib_get_sreg(ea_t ea, int rg) {
    return get_sreg(ea, rg);
}

// Set default segment register value for a segment
inline bool idalib_set_default_sreg_value(segment_t *sg, int rg, uint64_t value) {
    return set_default_sreg_value(sg, rg, value);
}

// Set segment register at next code
inline void idalib_set_sreg_at_next_code(ea_t ea1, ea_t ea2, int rg, uint64_t value) {
    set_sreg_at_next_code(ea1, ea2, rg, value);
}

// Split segment register range
inline bool idalib_split_sreg_range(ea_t ea, int rg, uint64_t value, int tag, bool silent) {
    return split_sreg_range(ea, rg, value, (uchar)tag, silent);
}

// Get segment register range info
inline bool idalib_get_sreg_range(ea_t ea, int rg, ea_t *start, ea_t *end, uint64_t *val, int *tag) {
    sreg_range_t out;
    if (get_sreg_range(&out, ea, rg)) {
        if (start) *start = out.start_ea;
        if (end) *end = out.end_ea;
        if (val) *val = out.val;
        if (tag) *tag = out.tag;
        return true;
    }
    return false;
}

// Get previous segment register range
inline bool idalib_get_prev_sreg_range(ea_t ea, int rg, ea_t *start, ea_t *end, uint64_t *val, int *tag) {
    sreg_range_t out;
    if (get_prev_sreg_range(&out, ea, rg)) {
        if (start) *start = out.start_ea;
        if (end) *end = out.end_ea;
        if (val) *val = out.val;
        if (tag) *tag = out.tag;
        return true;
    }
    return false;
}

// Set default data segment
inline void idalib_set_default_dataseg(uint64_t ds_sel) {
    set_default_dataseg(ds_sel);
}

// Get segment register ranges count
inline size_t idalib_get_sreg_ranges_qty(int rg) {
    return get_sreg_ranges_qty(rg);
}

// Delete segment register range
inline bool idalib_del_sreg_range(ea_t ea, int rg) {
    return del_sreg_range(ea, rg);
}
