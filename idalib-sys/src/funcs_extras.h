#pragma once

#include "funcs.hpp"
#include "typeinf.hpp"

// Function manipulation functions

// Add a function
inline bool idalib_add_func(ea_t ea1, ea_t ea2) {
    return add_func(ea1, ea2);
}

// Delete a function
inline bool idalib_del_func(ea_t ea) {
    return del_func(ea);
}

// Set function start address
inline int idalib_set_func_start(ea_t ea, ea_t newstart) {
    return set_func_start(ea, newstart);
}

// Set function end address
inline bool idalib_set_func_end(ea_t ea, ea_t newend) {
    return set_func_end(ea, newend);
}

// Update function info in the database
inline bool idalib_update_func(func_t *pfn) {
    return update_func(pfn);
}

// Get previous function by address
inline func_t *idalib_get_prev_func(ea_t ea) {
    return get_prev_func(ea);
}

// Get next function by address
inline func_t *idalib_get_next_func(ea_t ea) {
    return get_next_func(ea);
}

// Reanalyze a function
inline void idalib_reanalyze_function(func_t *pfn, ea_t ea1, ea_t ea2, bool analyze_parents) {
    reanalyze_function(pfn, ea1, ea2, analyze_parents);
}

// Find function bounds
inline int idalib_find_func_bounds(func_t *nfn, int flags) {
    return find_func_bounds(nfn, flags);
}

// Calculate function size
inline uint64_t idalib_calc_func_size(func_t *pfn) {
    return calc_func_size(pfn);
}

// Get function bitness (returns 0, 1, or 2 for 16/32/64 bits)
inline int idalib_get_func_bitness(const func_t *pfn) {
    return get_func_bitness(pfn);
}

// Set function visibility
inline void idalib_set_visible_func(func_t *pfn, bool visible) {
    set_visible_func(pfn, visible);
}

// Check if function is visible
inline bool idalib_is_visible_func(func_t *pfn) {
    return is_visible_func(pfn);
}

// Check if function returns
inline bool idalib_func_does_return(ea_t callee) {
    return func_does_return(callee);
}

// Reanalyze noret flag
inline bool idalib_reanalyze_noret_flag(ea_t ea) {
    return reanalyze_noret_flag(ea);
}

// Set instruction as noret
inline bool idalib_set_noret_insn(ea_t insn_ea, bool noret) {
    return set_noret_insn(insn_ea, noret);
}

// Check if function is locked
inline bool idalib_is_func_locked(const func_t *pfn) {
    return is_func_locked(pfn);
}

// Lock/unlock function range
inline void idalib_lock_func_range(const func_t *pfn, bool lock) {
    lock_func_range(pfn, lock);
}

// Append a function tail
inline bool idalib_append_func_tail(func_t *pfn, ea_t ea1, ea_t ea2) {
    return append_func_tail(pfn, ea1, ea2);
}

// Remove a function tail
inline bool idalib_remove_func_tail(func_t *pfn, ea_t tail_ea) {
    return remove_func_tail(pfn, tail_ea);
}

// Set tail owner
inline bool idalib_set_tail_owner(func_t *fnt, ea_t new_owner) {
    return set_tail_owner(fnt, new_owner);
}

// Get function chunk (works with both functions and tails)
inline func_t *idalib_get_fchunk(ea_t ea) {
    return get_fchunk(ea);
}

// Get nth function chunk
inline func_t *idalib_getn_fchunk(int n) {
    return getn_fchunk(n);
}

// Get function chunk count
inline size_t idalib_get_fchunk_qty() {
    return get_fchunk_qty();
}

// Get previous address in function
inline ea_t idalib_get_prev_func_addr(func_t *pfn, ea_t ea) {
    return get_prev_func_addr(pfn, ea);
}

// Get next address in function
inline ea_t idalib_get_next_func_addr(func_t *pfn, ea_t ea) {
    return get_next_func_addr(pfn, ea);
}

// Set function name if it's a jump function
inline int idalib_set_func_name_if_jumpfunc(func_t *pfn, const char *oldname) {
    return set_func_name_if_jumpfunc(pfn, oldname);
}

// Get function ranges into a string representation
inline rust::String idalib_get_func_ranges(func_t *pfn) {
    rangeset_t ranges;
    get_func_ranges(&ranges, pfn);
    qstring result;
    for (const range_t &r : ranges) {
        result.cat_sprnt("%llx-%llx ", (uint64)r.start_ea, (uint64)r.end_ea);
    }
    return rust::String(result.c_str());
}

// Apply FLIRT signature to address
inline int idalib_apply_idasgn_to(const char *signame, ea_t ea, bool is_startup) {
    return apply_idasgn_to(signame, ea, is_startup);
}

// Get number of loaded FLIRT signatures
inline int idalib_get_idasgn_qty() {
    return get_idasgn_qty();
}

// Plan to apply FLIRT signature
inline int idalib_plan_to_apply_idasgn(const char *fname) {
    return plan_to_apply_idasgn(fname);
}
