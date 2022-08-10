#include <iostream>
#include "random.h"
#include "wasm_structure.h"
#include "global_classes_list.h"
#include <unistd.h>
#include <fcntl.h>
#include "wasmer.h"

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
    wasm_store_t *store = wasm_store_new(engine);
    wasm_byte_vec_t binary;
    int sz = out.size();
    wasm_byte_vec_new_uninitialized(&binary, sz);
    memcpy(binary.data, out.buffer(), sz);
    delete wasm;
    wasm_module_t *module = wasm_module_new(store, &binary);
    if (!module)
    {
        // printf("> Error compiling module!\n");
        wasm_byte_vec_delete(&binary);
        wasm_store_delete(store);
        wasm_engine_delete(engine);
        return 0;
    }
    wasm_byte_vec_delete(&binary);

    wasi_config_t *config = wasi_config_new("wasi");
    wasi_config_capture_stdout(config);
    wasi_env_t *wasi_env = wasi_env_new(config);
    if (!wasi_env)
    {
        // printf("> Error building WASI env!\n");
        wasm_store_delete(store);
        wasm_engine_delete(engine);
        wasm_module_delete(module);
        return 0;
    }
    wasm_extern_vec_t imports;
    bool get_imports_result = wasi_get_imports(store, module, wasi_env, &imports);
    if (!get_imports_result)
    {
        //printf("> Error getting WASI imports!\n");
        wasm_store_delete(store);
        wasm_engine_delete(engine);
        wasm_module_delete(module);
        wasi_env_delete(wasi_env);
        return 0;
    }

    wasm_instance_t *instance =
        wasm_instance_new(store, module, &imports, NULL);
    if (!instance)
    {
        // printf("> Error instantiating module!\n");
        wasm_store_delete(store);
        wasm_engine_delete(engine);
        wasm_module_delete(module);
        wasi_env_delete(wasi_env);
        wasm_extern_vec_delete(&imports);
        return 0;
    }
    wasm_extern_vec_t exports;
    wasm_instance_exports(instance, &exports);
    if (exports.size == 0)
    {
        // printf("Error accessing exports!\n");
        wasm_store_delete(store);
        wasm_engine_delete(engine);
        wasm_module_delete(module);
        wasm_instance_delete(instance);
        wasi_env_delete(wasi_env);
        wasm_extern_vec_delete(&imports);
        return 0;
    }
    const wasm_func_t *run_func = wasm_extern_as_func(exports.data[0]);
    if (run_func == NULL)
    {
        //printf("> Error accessing export!\n");
        wasm_extern_vec_delete(&exports);
        wasm_store_delete(store);
        wasm_engine_delete(engine);
        wasm_module_delete(module);
        wasm_instance_delete(instance);
        wasi_env_delete(wasi_env);
        wasm_extern_vec_delete(&imports);
        return 0;
    }

    wasm_module_delete(module);
    wasm_instance_delete(instance);

    wasm_val_vec_t args = WASM_EMPTY_VEC;
    wasm_val_vec_t results = WASM_EMPTY_VEC;
    wasm_func_call(run_func, &args, &results);

    wasm_extern_vec_delete(&exports);
    wasm_store_delete(store);
    wasm_engine_delete(engine);
    wasi_env_delete(wasi_env);
    wasm_extern_vec_delete(&imports);

    return 0;
}