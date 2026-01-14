#pragma once

#include "typeinf.hpp"
#include "nalt.hpp"

#include "cxx.h"

// Type information operations

// Get type at an address as string
inline rust::String idalib_get_type_str(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea)) {
        qstring out;
        if (tif.print(&out)) {
            return rust::String(out.c_str());
        }
    }
    return rust::String();
}

// Set type at an address from string
inline bool idalib_set_type_str(ea_t ea, const char *type_str) {
    tinfo_t tif;
    if (parse_decl(&tif, nullptr, nullptr, type_str, PT_SIL)) {
        return set_tinfo(ea, &tif);
    }
    return false;
}

// Delete type at an address
inline bool idalib_del_tinfo_at(ea_t ea) {
    return set_tinfo(ea, nullptr);
}

// Get operand type at an address as string
inline rust::String idalib_get_op_type_str(ea_t ea, int n) {
    tinfo_t tif;
    if (get_op_tinfo(&tif, ea, n)) {
        qstring out;
        if (tif.print(&out)) {
            return rust::String(out.c_str());
        }
    }
    return rust::String();
}

// Set operand type at an address from string
inline bool idalib_set_op_type_str(ea_t ea, int n, const char *type_str) {
    tinfo_t tif;
    if (parse_decl(&tif, nullptr, nullptr, type_str, PT_SIL)) {
        return set_op_tinfo(ea, n, &tif);
    }
    return false;
}

// Get function type as string
inline rust::String idalib_get_func_type_str(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea) && tif.is_func()) {
        qstring out;
        if (tif.print(&out)) {
            return rust::String(out.c_str());
        }
    }
    return rust::String();
}

// Set function type from string
inline bool idalib_set_func_type_str(ea_t ea, const char *type_str) {
    tinfo_t tif;
    if (parse_decl(&tif, nullptr, nullptr, type_str, PT_SIL)) {
        if (tif.is_func()) {
            return apply_tinfo(ea, tif, TINFO_DEFINITE);
        }
    }
    return false;
}

// Get named type (from local types)
inline rust::String idalib_get_named_type_str(const char *name) {
    tinfo_t tif;
    if (tif.get_named_type(nullptr, name)) {
        qstring out;
        if (tif.print(&out)) {
            return rust::String(out.c_str());
        }
    }
    return rust::String();
}

// Check if a named type exists
inline bool idalib_named_type_exists(const char *name) {
    tinfo_t tif;
    return tif.get_named_type(nullptr, name);
}

// Get the ordinal of a named type (0 if not found)
inline uint32_t idalib_get_named_type_ordinal(const char *name) {
    return get_type_ordinal(nullptr, name);
}

// Get type by ordinal
inline rust::String idalib_get_numbered_type_str(uint32_t ordinal) {
    tinfo_t tif;
    if (tif.get_numbered_type(nullptr, ordinal)) {
        qstring out;
        if (tif.print(&out)) {
            return rust::String(out.c_str());
        }
    }
    return rust::String();
}

// Get number of local types
inline uint32_t idalib_get_ordinal_qty() {
    return get_ordinal_count(nullptr);
}

// Check if type is a struct
inline bool idalib_is_type_struct(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea)) {
        return tif.is_struct();
    }
    return false;
}

// Check if type is a union
inline bool idalib_is_type_union(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea)) {
        return tif.is_union();
    }
    return false;
}

// Check if type is an enum
inline bool idalib_is_type_enum(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea)) {
        return tif.is_enum();
    }
    return false;
}

// Check if type is a pointer
inline bool idalib_is_type_ptr(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea)) {
        return tif.is_ptr();
    }
    return false;
}

// Check if type is an array
inline bool idalib_is_type_array(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea)) {
        return tif.is_array();
    }
    return false;
}

// Check if type is a function
inline bool idalib_is_type_func(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea)) {
        return tif.is_func();
    }
    return false;
}

// Get type size
inline uint64_t idalib_get_type_size(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea)) {
        return tif.get_size();
    }
    return 0;
}

// Get named type size
inline uint64_t idalib_get_named_type_size(const char *name) {
    tinfo_t tif;
    if (tif.get_named_type(nullptr, name)) {
        return tif.get_size();
    }
    return 0;
}

// Parse a type declaration
inline bool idalib_parse_decl(const char *decl, rust::String *out_name, rust::String *out_type) {
    tinfo_t tif;
    qstring name;
    if (parse_decl(&tif, &name, nullptr, decl, PT_SIL)) {
        if (out_name) {
            *out_name = rust::String(name.c_str());
        }
        if (out_type) {
            qstring type_str;
            if (tif.print(&type_str)) {
                *out_type = rust::String(type_str.c_str());
            }
        }
        return true;
    }
    return false;
}

// Get compiler ID
inline uint8_t idalib_get_compiler_id() {
    return (uint8_t)default_compiler();
}

// Get compiler name
inline rust::String idalib_get_compiler_name_str() {
    const char *name = get_compiler_name(default_compiler());
    return name ? rust::String(name) : rust::String();
}

// Get compiler abbreviation
inline rust::String idalib_get_compiler_abbr_str() {
    const char *abbr = get_compiler_abbr(default_compiler());
    return abbr ? rust::String(abbr) : rust::String();
}

// Get ABI name
inline rust::String idalib_get_abi_name_str() {
    qstring out;
    if (get_abi_name(&out) > 0) {
        return rust::String(out.c_str());
    }
    return rust::String();
}

// Print type at address
inline rust::String idalib_print_type(ea_t ea, int prtype_flags) {
    qstring out;
    if (print_type(&out, ea, prtype_flags)) {
        return rust::String(out.c_str());
    }
    return rust::String();
}

// Get UDT (struct/union) member count
inline int idalib_get_udt_member_count(const char *type_name) {
    tinfo_t tif;
    if (tif.get_named_type(nullptr, type_name)) {
        udt_type_data_t udt;
        if (tif.get_udt_details(&udt)) {
            return udt.size();
        }
    }
    return -1;
}

// Get UDT member name by index
inline rust::String idalib_get_udt_member_name(const char *type_name, int idx) {
    tinfo_t tif;
    if (tif.get_named_type(nullptr, type_name)) {
        udt_type_data_t udt;
        if (tif.get_udt_details(&udt) && idx >= 0 && (size_t)idx < udt.size()) {
            return rust::String(udt[idx].name.c_str());
        }
    }
    return rust::String();
}

// Get UDT member type by index
inline rust::String idalib_get_udt_member_type(const char *type_name, int idx) {
    tinfo_t tif;
    if (tif.get_named_type(nullptr, type_name)) {
        udt_type_data_t udt;
        if (tif.get_udt_details(&udt) && idx >= 0 && (size_t)idx < udt.size()) {
            qstring out;
            if (udt[idx].type.print(&out)) {
                return rust::String(out.c_str());
            }
        }
    }
    return rust::String();
}

// Get UDT member offset by index
inline int64_t idalib_get_udt_member_offset(const char *type_name, int idx) {
    tinfo_t tif;
    if (tif.get_named_type(nullptr, type_name)) {
        udt_type_data_t udt;
        if (tif.get_udt_details(&udt) && idx >= 0 && (size_t)idx < udt.size()) {
            return udt[idx].offset / 8;  // Convert bits to bytes
        }
    }
    return -1;
}

// Get enum member count
inline int idalib_get_enum_member_count(const char *type_name) {
    tinfo_t tif;
    if (tif.get_named_type(nullptr, type_name)) {
        enum_type_data_t etd;
        if (tif.get_enum_details(&etd)) {
            return etd.size();
        }
    }
    return -1;
}

// Get enum member name by index
inline rust::String idalib_get_enum_member_name(const char *type_name, int idx) {
    tinfo_t tif;
    if (tif.get_named_type(nullptr, type_name)) {
        enum_type_data_t etd;
        if (tif.get_enum_details(&etd) && idx >= 0 && (size_t)idx < etd.size()) {
            return rust::String(etd[idx].name.c_str());
        }
    }
    return rust::String();
}

// Get enum member value by index
inline int64_t idalib_get_enum_member_value(const char *type_name, int idx) {
    tinfo_t tif;
    if (tif.get_named_type(nullptr, type_name)) {
        enum_type_data_t etd;
        if (tif.get_enum_details(&etd) && idx >= 0 && (size_t)idx < etd.size()) {
            return etd[idx].value;
        }
    }
    return 0;
}

// Get function argument count
inline int idalib_get_func_arg_count(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea) && tif.is_func()) {
        func_type_data_t ftd;
        if (tif.get_func_details(&ftd)) {
            return ftd.size();
        }
    }
    return -1;
}

// Get function argument name by index
inline rust::String idalib_get_func_arg_name(ea_t ea, int idx) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea) && tif.is_func()) {
        func_type_data_t ftd;
        if (tif.get_func_details(&ftd) && idx >= 0 && (size_t)idx < ftd.size()) {
            return rust::String(ftd[idx].name.c_str());
        }
    }
    return rust::String();
}

// Get function argument type by index
inline rust::String idalib_get_func_arg_type(ea_t ea, int idx) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea) && tif.is_func()) {
        func_type_data_t ftd;
        if (tif.get_func_details(&ftd) && idx >= 0 && (size_t)idx < ftd.size()) {
            qstring out;
            if (ftd[idx].type.print(&out)) {
                return rust::String(out.c_str());
            }
        }
    }
    return rust::String();
}

// Get function return type
inline rust::String idalib_get_func_rettype(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea) && tif.is_func()) {
        func_type_data_t ftd;
        if (tif.get_func_details(&ftd)) {
            qstring out;
            if (ftd.rettype.print(&out)) {
                return rust::String(out.c_str());
            }
        }
    }
    return rust::String();
}

// Get function calling convention
inline int idalib_get_func_cc(ea_t ea) {
    tinfo_t tif;
    if (get_tinfo(&tif, ea) && tif.is_func()) {
        func_type_data_t ftd;
        if (tif.get_func_details(&ftd)) {
            return ftd.get_cc();
        }
    }
    return 0;
}

// Create a new local type from string
inline uint32_t idalib_add_local_type(const char *decl, const char *name) {
    tinfo_t tif;
    if (parse_decl(&tif, nullptr, nullptr, decl, PT_SIL)) {
        return tif.set_named_type(nullptr, name, NTF_TYPE);
    }
    return 0;
}

// Delete a local type by name
inline bool idalib_del_local_type(const char *name) {
    return del_named_type(nullptr, name, NTF_TYPE);
}

// Import types from a til file
inline int idalib_add_til(const char *tilname) {
    return add_til(tilname, ADDTIL_DEFAULT);
}

// Delete til
inline bool idalib_del_til(const char *tilname) {
    return del_til(tilname);
}