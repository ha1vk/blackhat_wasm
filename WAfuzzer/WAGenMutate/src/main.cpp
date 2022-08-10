#include <iostream>
#include "random.h"
#include "wasm_structure.h"
#include "global_classes_list.h"
#include <unistd.h>
#include <fcntl.h>

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

int main()
{
    Random::init_fd();
    initList();
    //for (int i=0;i<0x1000;i++) {
        wasm_test();
    //}
}