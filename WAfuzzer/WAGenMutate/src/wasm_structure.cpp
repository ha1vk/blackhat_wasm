#include "wasm_structure.h"
#include "random.h"
#include "global_classes_list.h"
#include "custom_section.h"
#include "leb128.h"
#include <random>
#include <string.h>
#include <chrono>
#include <algorithm>
#include <fcntl.h>
#include <unistd.h>

void Wasm::WasmStructure::clean()
{
    int count = sections.size();
    if (count)
    {
        for (int i = 0; i < count; i++)
        {
            delete sections[i];
        }
        sections.clear();
    }
}

Wasm::WasmStructure::WasmStructure()
{
    memcpy(magic, "\0asm", 0x4);
    version = 0x1;
    context = new Context();
    data = nullptr;
}

Wasm::WasmStructure::WasmStructure(void *data, size_t len)
{
    memcpy(magic, "\0asm", 0x4);
    version = 0x1;
    context = new Context(new Random(data, len));
    data = nullptr;
}

Wasm::WasmStructure::WasmStructure(const char *path)
{
    memcpy(magic, "\0asm", 0x4);
    version = 0x1;
    int fd = open(path, O_RDONLY);
    data_len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0L, SEEK_SET);
    data = malloc(data_len);
    if (read(fd, data, data_len) != data_len)
    {
        puts("read data error!");
        abort();
    }
    close(fd);
    context = new Context(new Random(data, data_len));
}

void Wasm::WasmStructure::generate()
{
    clean();
    context->reset();
    int count = context->random->range(0, 0x10); // TODO

    // unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    // std::shuffle(Sections::sections_list.begin(), Sections::sections_list.end(), std::default_random_engine(seed));
    for (int i = 0; i < count; i++)
    {
        Sections::Section *sec;
        if (i < Sections::sections_list.size())
        {
            sec = Sections::sections_list[i]();
        }
        else
        {
            sec = new Sections::CustomSection();
        }
        sec->generate(context);
        sections.push_back(sec);
    }
}

void Wasm::WasmStructure::getEncode(DataOutputStream *out)
{
    out->write_buf(magic, 0x4);
    out->write_uint(version);
    int count = sections.size();
    for (int i = 0; i < count; i++)
    {
        sections[i]->getEncode(out);
    }
}

Wasm::WasmStructure::~WasmStructure()
{
    clean();
    if (context)
    {
        delete context;
        context = nullptr;
    }
    if (data)
    {
        free(data);
        data = nullptr;
    }
}