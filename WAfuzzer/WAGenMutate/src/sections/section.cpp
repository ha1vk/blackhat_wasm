#include "section.h"
#include "leb128.h"
#include "random.h"
#include "export_section.h"
#include "type_section.h"
#include "code_section.h"
#include "config.h"

void Sections::Section::clean()
{
    if (num_added)
    {
        for (int i = 0; i < num_added; i++)
        {
            delete types[i];
        }
        types.clear();
        num_added = 0;
    }
}
Sections::Section::Section()
{
    num_added = 0;
}

Sections::Section::SectionId Sections::Section::id()
{
    return Alias;
}

int Sections::Section::gen_num(Context *context)
{
    return context->random->range(0, 0x10);
}

void Sections::Section::generate(Context *context)
{
    clean();
    num_added = gen_num(context);
    types.resize(num_added);
    for (int i = 0; i < num_added; i++)
    {
        types[i] = getTypeEx();
        if (i == 0)
        {
            if (id() == Export)
            {
                ((ExportType *)types[i])->set_export_start(); // add a export _start function
            }
            else if (Config::verify && id() == Type)
            {
                ((FunctionType *)types[i])->set_start_function(); // Start function signature should be {}->{}
            }
        }
        if (id() == Code)
        {
            ((FunctionCode *)types[i])->set_index(i);
        }
        types[i]->generate(context);
    }
}

void Sections::Section::getEncode(DataOutputStream *out)
{
    DataOutputStream t(0x10);
    unsigned_to_leb128(num_added, &t);
    // printf("Type %d num_added=%d\n", id(), num_added);
    int n = t.size();
    DataOutputStream bytes;
    for (int i = 0; i < num_added; i++)
    {
        types[i]->getEncode(&bytes);
    }
    out->write_byte(id());                     // ID
    unsigned_to_leb128(n + bytes.size(), out); // PayloadLen
    out->write_from_data(&t);                  // Count
    out->write_from_data(&bytes);              // Entries
}

Sections::Section::~Section()
{
    clean();
}