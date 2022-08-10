#include <iostream>
#include "random.h"
#include "wasm_structure.h"
#include "global_classes_list.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <JavaScriptCore/JavaScript.h>

using namespace std;
using namespace Wasm;
using namespace Sections;

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
    //printf("%s\n",csource);
    JSGlobalContextRef context = JSGlobalContextCreate(0);
    JSValueRef exception;
    JSStringRef code = JSStringCreateWithUTF8CString(csource);
    JSStringRef file = JSStringCreateWithUTF8CString("");
    JSValueRef value = JSEvaluateScript(context, code, /* thisObject*/ 0, file, 1, &exception);
    //std::cout << "Value:  from JSCore! " << std::endl;
    JSStringRelease(code);
    JSStringRelease(file);
    JSGlobalContextRelease(context);
    
    delete wasm;
    free(buf);
    delete[] csource;
    return 0;
}
