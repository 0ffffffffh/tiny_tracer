#include "ProcessInfo.h"

//----

bool is_my_name(const s_module* mod, std::string name)
{
    if (!mod) {
        return false;
    }
    std::size_t found = mod->name.find(name);
    if (found != std::string::npos) {
        return true;
    }
    return false;
}

void ProcessInfo::addModuleSections(IMG Image, ADDRINT ImageBase)
{
    // enumerate sections within the analysed module
    for (SEC sec = IMG_SecHead(Image); SEC_Valid(sec); sec = SEC_Next(sec)) {
        s_module section;
        init_section(section, ImageBase, sec);
        m_Sections[section.start] = section;
    }
}

bool ProcessInfo::addModule(IMG Image)
{
    // Add module into a global map
    s_module mod;
    init_module(mod, Image);

    // if this module is an object of observation, add its sections also
    if (m_myPid == 0 && is_my_name(&mod, m_AnalysedApp)) {
        m_myPid = PIN_GetPid();
        myModuleBase = IMG_LoadOffset(Image);
        addModuleSections(Image, myModuleBase);
    }
    return true;
}

const bool ProcessInfo::isSectionChanged(ADDRINT Rva)
{
    // saved section (of the target module)
    static s_module* prevSec = nullptr;

    // current section of the target module (by RVA)
    const s_module* currSec = getSecByAddr(Rva);

    if (prevSec != currSec) {
        // update the stored section
        prevSec = (s_module*)currSec;
        return true;
    }
    return false;
}

