#pragma once

#include "netnode.hpp"

#include "cxx.h"

// Netnode operations for low-level database storage

// Convert ea to node index
inline uint64_t idalib_ea2node(ea_t ea) {
    return ea2node(ea);
}

// Convert node index to ea
inline ea_t idalib_node2ea(uint64_t ndx) {
    return node2ea(ndx);
}

// Create or find a netnode by name
inline uint64_t idalib_netnode_create(const char *name) {
    netnode n(name, 0, true);
    return (nodeidx_t)n;
}

// Find a netnode by name (returns BADNODE if not found)
inline uint64_t idalib_netnode_find(const char *name) {
    netnode n(name, 0, false);
    return (nodeidx_t)n;
}

// Kill a netnode
inline void idalib_netnode_kill(uint64_t nodeidx) {
    netnode n(nodeidx);
    n.kill();
}

// Get netnode name
inline rust::String idalib_netnode_get_name(uint64_t nodeidx) {
    qstring out;
    if (netnode_get_name(nodeidx, &out) > 0) {
        return rust::String(out.c_str());
    }
    return rust::String();
}

// Rename a netnode
inline bool idalib_netnode_rename(uint64_t nodeidx, const char *newname) {
    return netnode_rename(nodeidx, newname, strlen(newname));
}

// Get altval (alternative integer value)
inline uint64_t idalib_netnode_altval(uint64_t nodeidx, uint64_t alt, int tag) {
    return netnode_altval(nodeidx, alt, tag);
}

// Set altval
inline bool idalib_netnode_altset(uint64_t nodeidx, uint64_t alt, uint64_t value, int tag) {
    netnode n(nodeidx);
    return n.altset(alt, value, (uchar)tag);
}

// Delete altval
inline bool idalib_netnode_altdel(uint64_t nodeidx, uint64_t alt, int tag) {
    netnode n(nodeidx);
    return n.altdel(alt, (uchar)tag);
}

// Get supval (supplementary value)
inline rust::Vec<uint8_t> idalib_netnode_supval(uint64_t nodeidx, uint64_t alt, int tag) {
    rust::Vec<uint8_t> result;
    uchar buf[4096];
    ssize_t len = netnode_supval(nodeidx, alt, buf, sizeof(buf), tag);
    if (len > 0) {
        for (ssize_t i = 0; i < len; i++) {
            result.push_back(buf[i]);
        }
    }
    return result;
}

// Set supval
inline bool idalib_netnode_supset(uint64_t nodeidx, uint64_t alt, const uint8_t *data, size_t len, int tag) {
    return netnode_supset(nodeidx, alt, data, len, tag);
}

// Delete supval
inline bool idalib_netnode_supdel(uint64_t nodeidx, uint64_t alt, int tag) {
    return netnode_supdel(nodeidx, alt, tag);
}

// Get supstr (supplementary string value)
inline rust::String idalib_netnode_supstr(uint64_t nodeidx, uint64_t alt, int tag) {
    qstring out;
    if (netnode_qsupstr(nodeidx, &out, alt, tag) > 0) {
        return rust::String(out.c_str());
    }
    return rust::String();
}

// Get first supval index
inline uint64_t idalib_netnode_supfirst(uint64_t nodeidx, int tag) {
    return netnode_supfirst(nodeidx, tag);
}

// Get next supval index
inline uint64_t idalib_netnode_supnext(uint64_t nodeidx, uint64_t cur, int tag) {
    return netnode_supnext(nodeidx, cur, tag);
}

// Get last supval index
inline uint64_t idalib_netnode_suplast(uint64_t nodeidx, int tag) {
    return netnode_suplast(nodeidx, tag);
}

// Get previous supval index
inline uint64_t idalib_netnode_supprev(uint64_t nodeidx, uint64_t cur, int tag) {
    return netnode_supprev(nodeidx, cur, tag);
}

// Delete all supvals with a tag
inline bool idalib_netnode_supdel_all(uint64_t nodeidx, int tag) {
    return netnode_supdel_all(nodeidx, tag);
}

// Get hashval (hash table value by string key)
inline uint64_t idalib_netnode_hashval_long(uint64_t nodeidx, const char *idx, int tag) {
    return netnode_hashval_long(nodeidx, idx, tag);
}

// Set hashval
inline bool idalib_netnode_hashset(uint64_t nodeidx, const char *idx, const uint8_t *data, size_t len, int tag) {
    return netnode_hashset(nodeidx, idx, data, len, tag);
}

// Set hashval as integer
inline bool idalib_netnode_hashset_long(uint64_t nodeidx, const char *idx, uint64_t value, int tag) {
    netnode n(nodeidx);
    return n.hashset(idx, value, (uchar)tag);
}

// Delete hashval
inline bool idalib_netnode_hashdel(uint64_t nodeidx, const char *idx, int tag) {
    return netnode_hashdel(nodeidx, idx, tag);
}

// Get hashstr
inline rust::String idalib_netnode_hashstr(uint64_t nodeidx, const char *idx, int tag) {
    qstring out;
    if (netnode_qhashstr(nodeidx, &out, idx, tag) > 0) {
        return rust::String(out.c_str());
    }
    return rust::String();
}

// Get first hash key
inline rust::String idalib_netnode_hashfirst(uint64_t nodeidx, int tag) {
    qstring out;
    if (netnode_qhashfirst(nodeidx, &out, tag) > 0) {
        return rust::String(out.c_str());
    }
    return rust::String();
}

// Get next hash key
inline rust::String idalib_netnode_hashnext(uint64_t nodeidx, const char *idx, int tag) {
    qstring out;
    if (netnode_qhashnext(nodeidx, &out, idx, tag) > 0) {
        return rust::String(out.c_str());
    }
    return rust::String();
}

// Get blob size
inline size_t idalib_netnode_blobsize(uint64_t nodeidx, uint64_t start, int tag) {
    return netnode_blobsize(nodeidx, start, tag);
}

// Set blob
inline bool idalib_netnode_setblob(uint64_t nodeidx, const uint8_t *buf, size_t size, uint64_t start, int tag) {
    return netnode_setblob(nodeidx, buf, size, start, tag);
}

// Delete blob
inline int idalib_netnode_delblob(uint64_t nodeidx, uint64_t start, int tag) {
    return netnode_delblob(nodeidx, start, tag);
}

// Get node value (main blob)
inline rust::String idalib_netnode_valstr(uint64_t nodeidx) {
    qstring out;
    if (netnode_qvalstr(nodeidx, &out) > 0) {
        return rust::String(out.c_str());
    }
    return rust::String();
}

// Set node value
inline bool idalib_netnode_set_value(uint64_t nodeidx, const uint8_t *value, size_t length) {
    return netnode_set(nodeidx, value, length);
}

// Delete node value
inline bool idalib_netnode_delvalue(uint64_t nodeidx) {
    return netnode_delvalue(nodeidx);
}

// Check if netnodes are initialized
inline bool idalib_netnode_inited() {
    return netnode_inited();
}