#pragma once

#include "problems.hpp"

#include "cxx.h"

// Problem manipulation functions

// Remember a problem at an address
inline void idalib_remember_problem(int type, ea_t ea, const char *msg) {
    remember_problem((problist_id_t)type, ea, msg);
}

// Get problem at/after an address
inline ea_t idalib_get_problem(int type, ea_t lowea) {
    return get_problem((problist_id_t)type, lowea);
}

// Forget a problem at an address
inline bool idalib_forget_problem(int type, ea_t ea) {
    return forget_problem((problist_id_t)type, ea);
}

// Check if a problem is present at an address
inline bool idalib_is_problem_present(int type, ea_t ea) {
    return is_problem_present((problist_id_t)type, ea);
}

// Get problem name
inline rust::String idalib_get_problem_name(int type, bool longname) {
    const char *name = get_problem_name((problist_id_t)type, longname);
    return name ? rust::String(name) : rust::String();
}

// Get problem description
inline rust::String idalib_get_problem_desc(int type, ea_t ea) {
    qstring buf;
    if (get_problem_desc(&buf, (problist_id_t)type, ea) > 0) {
        return rust::String(buf.c_str());
    }
    return rust::String();
}
