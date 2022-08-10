#include <iostream>
#include "random.h"
#include "wasm_structure.h"
#include "global_classes_list.h"
#include <unistd.h>
#include <fcntl.h>
#include "wasmtime.h"
#include "wasi.h"

using namespace std;
using namespace Wasm;
using namespace Sections;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    Random::init_fd();
    initList();
    return 0;
}

wasm_trap_t *hello_callback(
    const wasm_val_vec_t *args, wasm_val_vec_t *results)
{
    // printf("Calling back...\n");
    // printf("> Hello World!\n");
    return NULL;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    DataOutputStream out;
    WasmStructure *wasm = new WasmStructure((void *)Data, Size);
    wasm->generate();
    wasm->getEncode(&out);
    wasm_engine_t *engine = wasm_engine_new();
    wasmtime_store_t *store = wasmtime_store_new(engine, NULL, NULL);
    wasmtime_context_t *context = wasmtime_store_context(store);
    wasmtime_linker_t *linker = wasmtime_linker_new(engine);
    wasmtime_error_t *error = wasmtime_linker_define_wasi(linker);
    if (error != NULL)
    {
        wasmtime_store_delete(store);
        wasm_engine_delete(engine);
        wasmtime_linker_delete(linker);
        // wasmtime_store_delete(context);

        return 0;
    }
    wasm_byte_vec_t binary;
    int sz = out.size();
    wasm_byte_vec_new_uninitialized(&binary, sz);
    memcpy(binary.data, out.buffer(), sz);
    delete wasm;
    wasmtime_module_t *module = NULL;
    error = wasmtime_module_new(engine, (uint8_t *)binary.data, binary.size, &module);
    if (error)
    {
        // printf("> Error compiling module!\n");
        wasm_byte_vec_delete(&binary);
        wasmtime_store_delete(store);
        wasm_engine_delete(engine);
        wasmtime_linker_delete(linker);
        // wasmtime_module_delete(module);
        return 0;
    }
    wasm_byte_vec_delete(&binary);

    wasi_config_t *wasi_config = wasi_config_new();
    assert(wasi_config);
    wasi_config_inherit_argv(wasi_config);
    wasi_config_inherit_env(wasi_config);
    wasi_config_inherit_stdin(wasi_config);
    wasi_config_inherit_stdout(wasi_config);
    wasi_config_inherit_stderr(wasi_config);
    wasm_trap_t *trap = NULL;
    error = wasmtime_context_set_wasi(context, wasi_config);
    if (error)
    {
        // exit_with_error("failed to instantiate WASI", error, NULL);
        wasmtime_store_delete(store);
        wasm_engine_delete(engine);
        wasmtime_module_delete(module);
        wasmtime_linker_delete(linker);
        // wasi_config_delete(wasi_config);
        //  wasmtime_store_delete(context);
        return 0;
    }

    error = wasmtime_linker_module(linker, context, "", 0, module);
    if (error)
    {
        // printf("> Error instantiating module!\n");
        wasmtime_store_delete(store);
        wasm_engine_delete(engine);
        wasmtime_module_delete(module);
        wasmtime_linker_delete(linker);
        // wasi_config_delete(wasi_config);
        //  wasmtime_store_delete(context);
        return 0;
    }
    wasmtime_func_t func;
    error = wasmtime_linker_get_default(linker, context, "", 0, &func);
    if (error)
    {
        wasmtime_store_delete(store);
        wasm_engine_delete(engine);
        wasmtime_module_delete(module);
        wasmtime_linker_delete(linker);
        // wasi_config_delete(wasi_config);
        //  wasmtime_store_delete(context);
        return 0;
    }

    wasmtime_func_call(context, &func, NULL, 0, NULL, 0, &trap);

    wasmtime_store_delete(store);
    wasm_engine_delete(engine);
    wasmtime_module_delete(module);
    wasmtime_linker_delete(linker);
    // wasi_config_delete(wasi_config);
    //   wasmtime_store_delete(context);
    return 0;
}