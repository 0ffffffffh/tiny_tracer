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
*/

#include "pin.H"
#include <iostream>

#include "ProcessInfo.h"
#include "TraceLog.h"

#define TOOL_NAME "TinyTracer"
#define VERSION "1.4.2"

#ifndef PAGE_SIZE
    #define PAGE_SIZE 0x1000
#endif

typedef enum {
    SHELLC_DO_NOT_FOLLOW = 0,    // trace only the main target module
    SHELLC_FOLLOW_FIRST = 1,     // follow only the first shellcode called from the main module
    SHELLC_FOLLOW_RECURSIVE = 2, // follow also the shellcodes called recursively from the the original shellcode
    SHELLC_OPTIONS_COUNT
} t_shellc_options;


/* ================================================================== */
// Global variables 
/* ================================================================== */

ProcessInfo pInfo;
TraceLog traceLog;

bool m_TraceRDTSC = false;
t_shellc_options m_FollowShellcode = SHELLC_DO_NOT_FOLLOW;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "", "Specify file name for the output");

KNOB<std::string> KnobModuleName(KNOB_MODE_WRITEONCE, "pintool",
    "m", "", "Analysed module name (by default same as app name)");

KNOB<bool> KnobShortLog(KNOB_MODE_WRITEONCE, "pintool",
    "s", "", "Use short call logging (without a full DLL path)");

KNOB<bool> KnobTraceRDTSC(KNOB_MODE_WRITEONCE, "pintool",
    "d", "", "Trace RDTSC");

KNOB<int> KnobFollowShellcode(KNOB_MODE_WRITEONCE, "pintool",
    "f", "", "Trace calls executed from shellcodes loaded in the memory:\n"
    "\t0 - trace only the main target module\n"
    "\t1 - follow only the first shellcode called from the main module \n"
    "\t2 - follow also the shellcodes called recursively from the the original shellcode\n"
);

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

t_shellc_options ConvertShcOption(int value)
{
    if (value >= SHELLC_OPTIONS_COUNT) {
        return SHELLC_FOLLOW_RECURSIVE;
    }
    return (t_shellc_options)value;
}

// compare strings, ignore case
bool isStrEqualI(const std::string &str1, const std::string &str2)
{
    if (str1.length() != str2.length()) {
        return false;
    }
    for (size_t i = 0; i < str1.length(); i++) {
        if (tolower(str1[i]) != tolower(str2[i])) {
            return false;
        }
    }
    return true;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */


VOID _SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo)
{
    // last shellcode to which the transition got redirected:
    static ADDRINT lastShellc = UNKNOWN_ADDR;

    const bool isTargetMy = pInfo.isMyAddress(addrTo);
    const bool isCallerMy = pInfo.isMyAddress(addrFrom);

    IMG targetModule = IMG_FindByAddress(addrTo);
    IMG callerModule = IMG_FindByAddress(addrFrom);

    ADDRINT pageFrom = GetPageOfAddr(addrFrom);
    ADDRINT pageTo = GetPageOfAddr(addrTo);

    //is it a transition from the traced module to a foreign module?
    if (isCallerMy && !isTargetMy) {
        ADDRINT RvaFrom = addr_to_rva(addrFrom);
        if (IMG_Valid(targetModule)) {
            const std::string func = get_func_at(addrTo);
            const std::string dll_name = IMG_Name(targetModule);
            traceLog.logCall(0, RvaFrom, true, dll_name, func);
        }
        else {
            //not in any of the mapped modules:
            lastShellc = pageTo; //save the beginning of this area
            traceLog.logCall(0, RvaFrom, lastShellc, addrTo);
        }
    }
    // trace calls from witin the last shellcode that was called from the traced module:
    if (m_FollowShellcode && !IMG_Valid(callerModule)) {

        const ADDRINT callerPage = pageFrom;
        if (callerPage != UNKNOWN_ADDR && callerPage == lastShellc) {

            if (IMG_Valid(targetModule)) {
                const std::string func = get_func_at(addrTo);
                const std::string dll_name = IMG_Name(targetModule);
                traceLog.logCall(callerPage, addrFrom, false, dll_name, func);
            }
            else if (pageFrom != pageTo
                && m_FollowShellcode == SHELLC_FOLLOW_RECURSIVE)
            {
                // set the called shellcode as the current:
                lastShellc = pageTo;
            }
        }
    }

    // is the address within the traced module?
    if (isTargetMy) {
        ADDRINT rva = addr_to_rva(addrTo); // convert to RVA

        // is it a transition from one section to another?
        if (pInfo.updateTracedModuleSection(rva)) {
            const s_module* sec = pInfo.getSecByAddr(rva);
            std::string curr_name = (sec) ? sec->name : "?";
            if (isCallerMy) {

                ADDRINT rvaFrom = addr_to_rva(addrFrom); // convert to RVA
                const s_module* prev_sec = pInfo.getSecByAddr(rvaFrom);
                std::string prev_name = (prev_sec) ? prev_sec->name : "?";
                traceLog.logNewSectionCalled(rvaFrom, prev_name, curr_name);
            }
            traceLog.logSectionChange(rva, curr_name);
        }
    }
}

VOID SaveTransitions(const ADDRINT prevVA, const ADDRINT Address)
{
    PIN_LockClient();
    _SaveTransitions(prevVA, Address);
    PIN_UnlockClient();
}

VOID RdtscCalled(const CONTEXT* ctxt)
{
    PIN_LockClient();

    ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    IMG currModule = IMG_FindByAddress(Address);
    const bool isCurrMy = pInfo.isMyAddress(Address);
    if (isCurrMy) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logRdtsc(0, rva);
    }
    if (m_FollowShellcode && !IMG_Valid(currModule)) {
        const ADDRINT start = GetPageOfAddr(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logRdtsc(start, rva);
        }
    }

    PIN_UnlockClient();
}

VOID CpuidCalled(const CONTEXT* ctxt)
{
    PIN_LockClient();

    ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    ADDRINT Param = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);

    IMG currModule = IMG_FindByAddress(Address);
    const bool isCurrMy = pInfo.isMyAddress(Address);
    if (isCurrMy) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logCpuid(0, rva, Param);
    }
    if (m_FollowShellcode && !IMG_Valid(currModule)) {
        const ADDRINT start = GetPageOfAddr(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logCpuid(start, rva, Param);
        }
    }

    PIN_UnlockClient();
}

ADDRINT _setTimer(const CONTEXT* ctxt, bool isEax)
{
    static UINT64 Timer = 0;
    UINT64 result = 0;

    if (Timer == 0) {
        ADDRINT edx = (ADDRINT)PIN_GetContextReg(ctxt, REG_GDX);
        ADDRINT eax = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);
        Timer = (UINT64(edx) << 32) | eax;
    }
    else {
        Timer += 100;
    }

    if (isEax) {
        result = Timer & 0xFFFFFFFFULL;
    }
    else {
        result = (Timer) >> 32;
    }
    return (ADDRINT)result;
}

ADDRINT AlterRdtscValueEdx(const CONTEXT* ctxt)
{
    ADDRINT result = 0;

    PIN_LockClient();
    result = _setTimer(ctxt, false);
    PIN_UnlockClient();

    return result;
}

ADDRINT AlterRdtscValueEax(const CONTEXT* ctxt)
{
    ADDRINT result = 0;

    PIN_LockClient();
    result = _setTimer(ctxt, true);
    PIN_UnlockClient();

    return result;
}


/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID InstrumentInstruction(INS ins, VOID *v)
{
    if (isStrEqualI(INS_Mnemonic(ins), "cpuid")) {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)CpuidCalled,
            IARG_CONTEXT,
            IARG_END
        );
    }

    if (INS_IsRDTSC(ins)) {
        if (m_TraceRDTSC) {
            INS_InsertCall(
                ins,
                IPOINT_BEFORE, (AFUNPTR)RdtscCalled,
                IARG_CONTEXT,
                IARG_END
            );
        }

        INS_InsertCall(
            ins, 
            IPOINT_AFTER, (AFUNPTR)AlterRdtscValueEdx,
            IARG_CONTEXT,
            IARG_RETURN_REGS, 
            REG_GDX,
            IARG_END);

        INS_InsertCall(ins, 
            IPOINT_AFTER, (AFUNPTR)AlterRdtscValueEax,
            IARG_CONTEXT,
            IARG_RETURN_REGS,
            REG_GAX,
            IARG_END);
    }

    if ((INS_IsControlFlow(ins) || INS_IsFarJump(ins))) {
        INS_InsertCall(
            ins, 
            IPOINT_BEFORE, (AFUNPTR)SaveTransitions,
            IARG_INST_PTR,
            IARG_BRANCH_TARGET_ADDR,
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
    if (ctxtTo == NULL || ctxtFrom == NULL) return;

    PIN_LockClient();
    const ADDRINT addrFrom = (ADDRINT)PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
    const ADDRINT addrTo = (ADDRINT)PIN_GetContextReg(ctxtTo, REG_INST_PTR);
    _SaveTransitions(addrFrom, addrTo);
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
    m_FollowShellcode = ConvertShcOption(KnobFollowShellcode.Value());
    m_TraceRDTSC = KnobTraceRDTSC.Value();

    // Register function to be called for every loaded module
    IMG_AddInstrumentFunction(ImageLoad, NULL);

    // Register function to be called before every instruction
    INS_AddInstrumentFunction(InstrumentInstruction, NULL);

    // Register context changes
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

