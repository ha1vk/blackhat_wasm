#include <iostream>
#include "random.h"
#include "wasm_structure.h"
#include "global_classes_list.h"
#include <unistd.h>
#include <fcntl.h>

#include "include/libplatform/libplatform.h"
#include "include/v8-context.h"
#include "include/v8-initialization.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-primitive.h"
#include "include/v8-script.h"

using namespace std;
using namespace Wasm;
using namespace Sections;
std::unique_ptr<v8::Platform> platform;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    Random::init_fd();
    initList();
    // Initialize V8.
    v8::V8::InitializeICUDefaultLocation("/mnt/hgfs/chromium/WAfuzzer/fuzzer_v8");
    v8::V8::InitializeExternalStartupData("/mnt/hgfs/chromium/WAfuzzer/fuzzer_v8");
    platform = v8::platform::NewDefaultPlatform();
    v8::V8::InitializePlatform(platform.get());
    v8::V8::Initialize();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    DataOutputStream out;
    WasmStructure *wasm = new WasmStructure((void *)Data, Size);
    wasm->generate();
    wasm->getEncode(&out);
    int sz = out.size();
    char *buf = (char *)calloc(sz, 7);
    const unsigned char *data = out.buffer();
    char tmp[0x7];
    for (int i = 0; i < sz; i++)
    {
        if (i != sz - 1)
        {
            sprintf(tmp, "0x%02x,", data[i]);
            memcpy(buf + i * 5, tmp, 5);
        }
        else
        {
            sprintf(tmp, "0x%02x", data[i]);
            memcpy(buf + i * 5, tmp, 4);
        }
    }
    char *csource = new char[sz * 7 + 0x300];
    const char csource_fmt[] = R"(
            let bytes = new Uint8Array([%s]);
            let module = new WebAssembly.Module(bytes);
            let instance = new WebAssembly.Instance(module);
            instance.exports._start();
        )";
    sprintf(csource, csource_fmt, buf);
    int csource_len = strlen(csource);
    // printf(csource);
    //  Create a new Isolate and make it the current one.
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator =
        v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    v8::Isolate *isolate = v8::Isolate::New(create_params);
    {
        v8::Isolate::Scope isolate_scope(isolate);

        // Create a stack-allocated handle scope.
        v8::HandleScope handle_scope(isolate);

        // Create a new context.
        v8::Local<v8::Context> context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);

        // Create a string containing the JavaScript source code.
        v8::Local<v8::String> source =
            v8::String::NewFromUtf8(isolate, csource, v8::NewStringType::kNormal, csource_len).ToLocalChecked();

        // Compile the source code.
        v8::Local<v8::Script> script =
            v8::Script::Compile(context, source).ToLocalChecked();

        // Run the script to get the result.
        v8::MaybeLocal<v8::Value> result = script->Run(context);

        //printf("aaaaaaaaaaaa\n");
    }

    delete wasm;
    free(buf);
    delete[] csource;
    // Dispose the isolate and tear down V8.
    isolate->Dispose();
    /*v8::V8::Dispose();
    v8::V8::ShutdownPlatform();*/
    delete create_params.array_buffer_allocator;
    return 0;
}
