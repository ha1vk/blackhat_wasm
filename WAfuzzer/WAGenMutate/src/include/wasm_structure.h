#ifndef WASM_STRUCT_H
#define WASM_STRUCT_H

#include <stdint.h>
#include <vector>
#include "section.h"

using std::vector;

namespace Wasm
{
    class WasmStructure
    {
    private:
        unsigned char magic[4];
        uint32_t version;
        vector<Sections::Section *> sections;
        Context *context;
        void *data;
        unsigned data_len;
        
        void clean();

    public:
        WasmStructure();
        WasmStructure(void *,size_t);
        WasmStructure(const char *);
        void generate();
        void getEncode(DataOutputStream *out);
        ~WasmStructure();
    };
}
#endif