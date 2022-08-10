#include <iostream>
#include "random.h"
#include "wasm_structure.h"
#include "global_classes_list.h"
#include <unistd.h>
#include <fcntl.h>
#include "wasm3.h"
#include "m3_api_wasi.h"

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
    M3Result result = m3Err_none;

    IM3Environment env = m3_NewEnvironment();
    if (env)
    {
        IM3Runtime runtime = m3_NewRuntime(env, 128, NULL);
        if (runtime)
        {
            IM3Module module = NULL;
            result = m3_ParseModule(env, &module, out.buffer(), out.size());
            if (module)
            {
                result = m3_LoadModule(runtime, module);
                if (result == 0)
                {
                    m3_LinkWASI(module);
                    IM3Function f = NULL;
                    result = m3_FindFunction(&f, runtime, "_start");
                    if (f)
                    {
                        m3_CallV(f, 10);
                    }
                }
                else
                {
                    m3_FreeModule(module);
                }
            }

            m3_FreeRuntime(runtime);
        }
        m3_FreeEnvironment(env);
    }
    delete wasm;
    return 0;
}