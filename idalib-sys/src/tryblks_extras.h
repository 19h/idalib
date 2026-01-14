#pragma once

#include "tryblks.hpp"

#include "cxx.h"

// Try/catch block manipulation functions

// Find SEH handler for an address
inline ea_t idalib_find_syseh(ea_t ea) {
    return find_syseh(ea);
}

// Check if address is in a try block
inline bool idalib_is_ea_tryblks(ea_t ea, uint32_t flags) {
    return is_ea_tryblks(ea, flags);
}

// Delete try blocks in a range
inline void idalib_del_tryblks(ea_t start, ea_t end) {
    range_t range(start, end);
    del_tryblks(range);
}

// Get number of try blocks in a range
inline size_t idalib_get_tryblks_qty(ea_t start, ea_t end) {
    range_t range(start, end);
    tryblks_t tbv;
    return get_tryblks(&tbv, range);
}
