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

/*!
* This function is called before every intruction to be executed.
* @param[in]   Address    address of the instruction to be executed
* @note use atomic operations for multi-threaded applications
*/

VOID _SaveTransitions(const CONTEXT* ctxt)
{
    ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    // previous address
    static ADDRINT prevVA = UNKNOWN_ADDR;

    // last shellcode to which the transition got redirected:
    static ADDRINT lastShellc = UNKNOWN_ADDR;

    const bool isCurrMy = pInfo.isMyAddress(Address);
    const bool isPrevMy = pInfo.isMyAddress(prevVA);

    IMG currModule = IMG_FindByAddress(Address);
    IMG prevModule = IMG_FindByAddress(prevVA);
    
    //is it a transition from the traced module to a foreign module?
    if (!isCurrMy && isPrevMy && prevVA != UNKNOWN_ADDR) {
        ADDRINT prevRVA = addr_to_rva(prevVA);
        if (IMG_Valid(currModule)) {
            const std::string func = get_func_at(Address);
            const std::string dll_name = IMG_Name(currModule);
            traceLog.logCall(0, prevRVA, true, dll_name, func);
        }
        else {
            //not in any of the mapped modules:
            lastShellc = GetPageOfAddr(Address); //save the beginning of this area
            traceLog.logCall(prevRVA, lastShellc, Address);
        }
    }
    // trace calls from witin the last shellcode that was called from the traced module:
    if (m_FollowShellcode && !IMG_Valid(prevModule) && IMG_Valid(currModule)) {
        const ADDRINT start = GetPageOfAddr(prevVA);
        if (start != UNKNOWN_ADDR && start == lastShellc) {
            const std::string func = get_func_at(Address);
            const std::string dll_name = IMG_Name(currModule);
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
}

VOID SaveTransitions(const CONTEXT* ctxt)
{
    PIN_LockClient();
    _SaveTransitions(ctxt);
    PIN_UnlockClient();
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
* Insert call to the SaveTranitions() analysis routine before every instruction
* of the trace.
* This function is called every time a new trace is encountered.
* @param[in]   trace    trace to be instrumented
* @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
*                       function call
*/

VOID InstrumentInstruction(INS ins, VOID *v)
{
    if (INS_IsControlFlow(ins) || INS_IsIndirectControlFlow(ins)) {
        INS_InsertCall(
            ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)SaveTransitions,
            IARG_CONTEXT,
            IARG_END
        );
    }
}

VOID ImageLoad(IMG Image, VOID *v)
{
    PIN_LockClient();
    pInfo.addModule(Image);
    PIN_UnlockClient();
}

static void OnCtxChange(THREADID threadIndex,
    CONTEXT_CHANGE_REASON reason,
    const CONTEXT *ctxtFrom,
    CONTEXT *ctxtTo,
    INT32 info,
    VOID *v)
{
    _SaveTransitions(ctxtTo);
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
    IMG_AddInstrumentFunction(ImageLoad, NULL);

    // Register function to be called before every instruction
    INS_AddInstrumentFunction(InstrumentInstruction, NULL);

    PIN_AddContextChangeFunction(OnCtxChange, NULL);

    std::cerr << "===============================================" << std::endl;
    std::cerr << "This application is instrumented by " << TOOL_NAME << " v." << VERSION << std::endl;
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

