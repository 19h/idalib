#pragma once

#include "xref.hpp"

// Cross-reference manipulation functions

// Add a code cross-reference
inline bool idalib_add_cref(ea_t from, ea_t to, int type) {
    return add_cref(from, to, (cref_t)type);
}

// Delete a code cross-reference
inline bool idalib_del_cref(ea_t from, ea_t to, bool expand) {
    return del_cref(from, to, expand);
}

// Add a data cross-reference
inline bool idalib_add_dref(ea_t from, ea_t to, int type) {
    return add_dref(from, to, (dref_t)type);
}

// Delete a data cross-reference
inline void idalib_del_dref(ea_t from, ea_t to) {
    del_dref(from, to);
}

// Get the type character for a cross-reference
inline char idalib_xrefchar(int xrtype) {
    return xrefchar(xrtype);
}

// Check if there's a jump or flow xref to the address
inline bool idalib_has_jump_or_flow_xref(ea_t ea) {
    return has_jump_or_flow_xref(ea);
}

// Create cross-references from an instruction
inline bool idalib_create_xrefs_from(ea_t ea) {
    return create_xrefs_from(ea);
}

// Delete all cross-references from an address
inline void idalib_delete_all_xrefs_from(ea_t ea, bool expand) {
    delete_all_xrefs_from(ea, expand);
}

// Get first data reference from an address
inline ea_t idalib_get_first_dref_from(ea_t from) {
    return get_first_dref_from(from);
}

// Get next data reference from an address
inline ea_t idalib_get_next_dref_from(ea_t from, ea_t current) {
    return get_next_dref_from(from, current);
}

// Get first data reference to an address
inline ea_t idalib_get_first_dref_to(ea_t to) {
    return get_first_dref_to(to);
}

// Get next data reference to an address
inline ea_t idalib_get_next_dref_to(ea_t to, ea_t current) {
    return get_next_dref_to(to, current);
}

// Get first code reference from an address
inline ea_t idalib_get_first_cref_from(ea_t from) {
    return get_first_cref_from(from);
}

// Get next code reference from an address
inline ea_t idalib_get_next_cref_from(ea_t from, ea_t current) {
    return get_next_cref_from(from, current);
}

// Get first code reference to an address
inline ea_t idalib_get_first_cref_to(ea_t to) {
    return get_first_cref_to(to);
}

// Get next code reference to an address
inline ea_t idalib_get_next_cref_to(ea_t to, ea_t current) {
    return get_next_cref_to(to, current);
}

// Get first far code reference from an address
inline ea_t idalib_get_first_fcref_from(ea_t from) {
    return get_first_fcref_from(from);
}

// Get next far code reference from an address
inline ea_t idalib_get_next_fcref_from(ea_t from, ea_t current) {
    return get_next_fcref_from(from, current);
}

// Get first far code reference to an address
inline ea_t idalib_get_first_fcref_to(ea_t to) {
    return get_first_fcref_to(to);
}

// Get next far code reference to an address
inline ea_t idalib_get_next_fcref_to(ea_t to, ea_t current) {
    return get_next_fcref_to(to, current);
}
