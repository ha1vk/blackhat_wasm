#include <iostream>
#include "random.h"
#include "wasm_structure.h"
#include "global_classes_list.h"
#include <unistd.h>
#include <fcntl.h>

using namespace std;

using namespace Wasm;

using namespace Sections;

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        printf("usage: %s data_path out_path\n", argv[0]);
        return -1;
    }
    Random::init_fd();
    initList();
    int f = open(argv[1], O_RDONLY);
    size_t sz = lseek(f, 0, SEEK_END);
    lseek(f, 0, SEEK_SET);
    char *buf = new char[sz];
    read(f, buf, sz);
    close(f);
    DataOutputStream out;
    WasmStructure *wasm = new WasmStructure(buf, sz);
    wasm->generate();
    wasm->getEncode(&out);
    out.write_to_file(argv[2]);
    delete wasm;
    delete[] buf;
}