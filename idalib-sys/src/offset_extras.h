#pragma once

#include "offset.hpp"

#include "cxx.h"

// Offset manipulation functions

// Get default reference type for an address
inline int idalib_get_default_reftype(ea_t ea) {
    return (int)get_default_reftype(ea);
}

// Convert operand to offset
inline bool idalib_op_offset(ea_t ea, int n, int type, ea_t target, ea_t base, int64_t tdelta) {
    return op_offset(ea, n, (reftype_t)type, target, base, tdelta);
}

// Get offset expression
inline rust::String idalib_get_offset_expression(ea_t ea, int n, ea_t from, int64_t offset, int geteflag) {
    qstring buf;
    if (get_offset_expression(&buf, ea, n, from, offset, geteflag) > 0) {
        return rust::String(buf.c_str());
    }
    return rust::String();
}

// Check if address can be 32-bit offset
inline ea_t idalib_can_be_off32(ea_t ea) {
    return can_be_off32(ea);
}

// Calculate offset base
inline ea_t idalib_calc_offset_base(ea_t ea, int n) {
    return calc_offset_base(ea, n);
}

// Calculate probable base by value
inline ea_t idalib_calc_probable_base_by_value(ea_t ea, uint64_t off) {
    return calc_probable_base_by_value(ea, off);
}

// Set reference info
inline bool idalib_set_refinfo(ea_t ea, int n, int type, ea_t target, ea_t base, int64_t tdelta) {
    return set_refinfo(ea, n, (reftype_t)type, target, base, tdelta);
}

// Get reference info
inline bool idalib_get_refinfo(ea_t ea, int n, int *type, ea_t *target, ea_t *base, int64_t *tdelta) {
    refinfo_t ri;
    if (get_refinfo(&ri, ea, n)) {
        if (type) *type = (int)ri.type();
        if (target) *target = ri.target;
        if (base) *base = ri.base;
        if (tdelta) *tdelta = ri.tdelta;
        return true;
    }
    return false;
}

// Delete reference info
inline bool idalib_del_refinfo(ea_t ea, int n) {
    return del_refinfo(ea, n);
}
