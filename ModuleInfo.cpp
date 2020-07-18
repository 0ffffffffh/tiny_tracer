#include "ModuleInfo.h"

bool init_module(s_module &mod, const ADDRINT &Address)
{
    IMG Image = IMG_FindByAddress(Address);
    if (!IMG_Valid(Image)) {
        mod.is_valid = false;
        return false;
    }
    return init_module(mod, Image);
}

bool init_module(s_module &mod, const IMG &Image)
{
    if (!IMG_Valid(Image)) {
        mod.is_valid = false;
        return false;
    }
    mod.name = std::string(IMG_Name(Image));
    mod.start = IMG_LoadOffset(Image);
    mod.end = mod.start + IMG_SizeMapped(Image);
    mod.is_valid = true;
    return true;
}

bool init_section(s_module &section, const ADDRINT &ImageBase, const SEC &sec)
{
    if (SEC_Address(sec) < ImageBase) {
        return false;
    }
    section.name = SEC_Name(sec);
    section.start = SEC_Address(sec) - ImageBase;
    section.end = section.start + SEC_Size(sec);
    return true;
}

const s_module* get_by_addr(ADDRINT Address, std::map<ADDRINT, s_module> &modules)
{
    std::map<ADDRINT, s_module>::iterator bound = modules.upper_bound(Address);
    std::map<ADDRINT, s_module>::iterator itr = modules.begin();

    for (; itr != bound; itr++) {
        s_module &mod = itr->second;
        if (Address >= mod.start && Address < mod.end) {
            return &mod;
        }
    }
    return nullptr;
}

std::string get_func_at(ADDRINT callAddr)
{
    IMG pImg = IMG_FindByAddress(callAddr);
    RTN rtn = RTN_FindByAddress(callAddr);
    if (IMG_Valid(pImg) && RTN_Valid(rtn)) {
        return RTN_Name(rtn);
    }
    return "";
}

ADDRINT get_mod_base(ADDRINT Address)
{
    IMG img = IMG_FindByAddress(Address);
    if (IMG_Valid(img)) {
        const ADDRINT base = IMG_LoadOffset(img);
        return base;
    }
    return UNKNOWN_ADDR;
}

ADDRINT get_base(ADDRINT Address)
{
    ADDRINT base = get_mod_base(Address);
    if (base != UNKNOWN_ADDR) {
        return base;
    }
    return GetPageOfAddr(Address);
}

ADDRINT addr_to_rva(ADDRINT Address)
{
    ADDRINT base = get_base(Address);
    if (base == UNKNOWN_ADDR) {
        return Address;
    }
    return Address - base;
}
