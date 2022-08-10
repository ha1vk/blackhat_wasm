#include <iostream>
#include "random.h"
#include "wasm_structure.h"
#include "global_classes_list.h"
#include <unistd.h>
#include <fcntl.h>
#include "wasmedge/wasmedge.h"

using namespace std;

using namespace Wasm;

using namespace Sections;

void wasm_test()
{
    DataOutputStream out;
    WasmStructure *wasm = new WasmStructure();
    wasm->generate();
    wasm->getEncode(&out);
    out.write_to_file("/home/sea/Desktop/1.wasm");
    delete wasm;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    Random::init_fd();
    initList();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    DataOutputStream out;
    WasmStructure *wasm = new WasmStructure((void *)Data, Size);
    wasm->generate();
    wasm->getEncode(&out);
    WasmEdge_ConfigureContext *ConfCxt = WasmEdge_ConfigureCreate();
    WasmEdge_ConfigureAddProposal(ConfCxt, WasmEdge_Proposal_MultiMemories);
    WasmEdge_ConfigureAddHostRegistration(ConfCxt, WasmEdge_HostRegistration_Wasi);
    WasmEdge_VMContext *VM = WasmEdge_VMCreate(ConfCxt, nullptr);
    WasmEdge_ConfigureDelete(ConfCxt);
    WasmEdge_Async *AsyncCxt = WasmEdge_VMAsyncRunWasmFromBuffer(
        VM, out.buffer(), out.size(), WasmEdge_StringWrap("_start", 6), nullptr,
        0);
    WasmEdge_AsyncWaitFor(AsyncCxt, 5);
    WasmEdge_Result Res = WasmEdge_AsyncGet(AsyncCxt, nullptr, 0);
    WasmEdge_ResultOK(Res);
    WasmEdge_AsyncDelete(AsyncCxt);
    WasmEdge_VMDelete(VM);
    delete wasm;
    return 0;
}

/*int main()
{
    Random::init_fd();
    initList();
    // for (int i=0;i<0x1000;i++) {
    wasm_test();
    //}
}*/