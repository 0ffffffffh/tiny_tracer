/*
* TinyTracer, CC by: hasherezade@gmail.com
* Runs with: Intel PIN (https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)
*
* Prints to <output_file> addresses of transitions from one sections to another
* (helpful in finding OEP of packed file)
* args:
* -m    <module_name> ; Analysed module name (by default same as app name)
* -o    <output_path> Output file
*
* saves PID in <output_file>.pid
*/

#include "pin.H"
#include <iostream>

#include "ProcessInfo.h"
#include "TraceLog.h"

#define TOOL_NAME "TinyTracer"
#ifndef PAGE_SIZE
    #define PAGE_SIZE 0x1000
#endif

/* ================================================================== */
// Global variables 
/* ================================================================== */

ProcessInfo pInfo;
TraceLog traceLog;

bool m_FollowShellcode = false;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "", "specify file name for the output");

KNOB<std::string> KnobModuleName(KNOB_MODE_WRITEONCE, "pintool",
    "m", "", "Analysed module name (by default same as app name)");

KNOB<bool> KnobShortLog(KNOB_MODE_WRITEONCE, "pintool",
    "s", "", "Use short call logging (without a full DLL path)");

KNOB<bool> KnobFollowShellcode(KNOB_MODE_WRITEONCE, "pintool",
    "f", "", "Trace calls executed from shellcodes loaded in the memory");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
*  Print out help message.
*/
INT32 Usage()
{
    std::cerr << "This tool prints out : " << std::endl <<
        "Addresses of redirections into to a new sections. Called API functions.\n" << std::endl;

    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

ADDRINT get_mod_base(ADDRINT Address)
{
    const s_module* mod_ptr = pInfo.getModByAddr(Address);
    if (mod_ptr) {
        return mod_ptr->start;
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

/*!
* This function is called for every basic block when it is about to be executed.
* @param[in]   numInstInBbl    number of instructions in the basic block
* @note use atomic operations for multi-threaded applications
*/
VOID SaveTransitions(ADDRINT Address, UINT32 numInstInBbl)
{
    PIN_LockClient();

    // previous address
    static ADDRINT prevVA = UNKNOWN_ADDR;

    // last shellcode to which the transition got redirected:
    static ADDRINT lastShellc = UNKNOWN_ADDR;

    const bool isCurrMy = pInfo.isMyAddress(Address);
    const bool isPrevMy = pInfo.isMyAddress(prevVA);
    const s_module* prevModule = pInfo.getModByAddr(prevVA);
    const s_module* mod_ptr = pInfo.getModByAddr(Address);

    //is it a transition from the traced module to a foreign module?
    if (!isCurrMy && isPrevMy && prevVA != UNKNOWN_ADDR) {
        ADDRINT prevRVA = addr_to_rva(prevVA);
        if (mod_ptr) {
            const std::string func = get_func_at(Address);
            const std::string dll_name = mod_ptr->name;
            traceLog.logCall(0, prevRVA, true, dll_name, func);
        }
        else {
            //not in any of the mapped modules:
            lastShellc = GetPageOfAddr(Address); //save the beginning of this area
            traceLog.logCall(prevRVA, lastShellc, Address);
        }
    }
    // trace calls from witin the last shellcode that was called from the traced module:
    if (m_FollowShellcode && !prevModule && mod_ptr) {
        const ADDRINT start = GetPageOfAddr(prevVA);
        if (start != UNKNOWN_ADDR && start == lastShellc) {
            const std::string func = get_func_at(Address);
            const std::string dll_name = mod_ptr->name;
            traceLog.logCall(start, prevVA, false, dll_name, func);
        }
    }

    // is the address within the traced module?
    if (isCurrMy) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA

        // is it a transition from one section to another?
        if (pInfo.isSectionChanged(rva)) {
            const s_module* sec = pInfo.getSecByAddr(rva);
            std::string curr_name = (sec) ? sec->name : "?";
            if (prevVA != UNKNOWN_ADDR && isPrevMy) {

                ADDRINT prevRva = addr_to_rva(prevVA); // convert to RVA
                const s_module* prev_sec = pInfo.getSecByAddr(prevRva);
                std::string prev_name = (prev_sec) ? prev_sec->name : "?";
                traceLog.logNewSectionCalled(prevRva, prev_name, curr_name);
            }
            traceLog.logSectionChange(rva, curr_name);
        }
    }

    // update saved
    prevVA = Address;

    PIN_UnlockClient();
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
* Insert call to the SaveTranitions() analysis routine before every basic block
* of the trace.
* This function is called every time a new trace is encountered.
* @param[in]   trace    trace to be instrumented
* @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
*                       function call
*/
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to SaveTranitions() before every basic block
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)SaveTransitions,
                IARG_INST_PTR,
                IARG_UINT32, BBL_NumIns(bbl), IARG_END);
        }
    }
}

VOID ImageLoad(IMG Image, VOID *v)
{
    PIN_LockClient();
    pInfo.addModule(Image);
    PIN_UnlockClient();
}

/*!
* The main procedure of the tool.
* This function is called when the application image is loaded but not yet started.
* @param[in]   argc            total number of elements in the argv array
* @param[in]   argv            array of command line arguments,
*                              including pin -t <toolname> -- ...
*/

int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 

    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
    
    std::string app_name = KnobModuleName.Value();
    if (app_name.length() == 0) {
        // init App Name:
        for (int i = 1; i < (argc - 1); i++) {
            if (strcmp(argv[i], "--") == 0) {
                app_name = argv[i + 1];
                break;
            }
        }
    }

    pInfo.init(app_name);

    // init output file:
    traceLog.init(KnobOutputFile.Value(), KnobShortLog.Value());
    m_FollowShellcode = KnobFollowShellcode.Value();

    // Register function to be called for every loaded module
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(Trace, 0);

    std::cerr << "===============================================" << std::endl;
    std::cerr << "This application is instrumented by " << TOOL_NAME << std::endl;
    std::cerr << "Tracing module: " << app_name << std::endl;
    if (!KnobOutputFile.Value().empty())
    {
        std::cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << std::endl;
    }
    std::cerr << "===============================================" << std::endl;

    // Start the program, never returns
    PIN_StartProgram();
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

