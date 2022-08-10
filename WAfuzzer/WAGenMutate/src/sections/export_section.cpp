#include "export_section.h"
#include "random.h"
#include "leb128.h"
#include <string.h>

void Sections::ExportType::clean()
{
    if (name)
    {
        free(name);
        name = nullptr;
    }
}
Sections::ExportType::ExportType()
{
    name = nullptr;
    export_start = false;
}

void Sections::ExportType::set_export_start()
{
    export_start = true;
}

void Sections::ExportType::generate(Context *context)
{
    if (!export_start)
    {
        name_len = context->random->range(0, 0x10000);
        name = (char *)malloc(name_len);
        for (int i = 0; i < name_len; i++)
        {
            name[i] = 'e';
        }
        type = CHOICE(itemKind);
        idx = context->random->integer();
    }
    else
    {
        name = strdup("_start");
        name_len = strlen(name);
        type = Function;
        if (context->code_count == 0)
        {
            idx = 0;
        }
        else
        {
            idx = context->random->selector(context->code_count);
        }
    }
}
void Sections::ExportType::getEncode(DataOutputStream *out)
{
    unsigned_to_leb128(name_len, out);
    for (int i = 0; i < name_len; i++)
    {
        out->write_byte(name[i]);
    }
    out->write_byte(type);
    unsigned_to_leb128(idx, out);
}

Sections::ExportType::~ExportType()
{
    clean();
}

int Sections::ExportSection::gen_num(Context *context)
{
    return 1; //TODO
}

Sections::Section::SectionId Sections::ExportSection::id()
{
    return SectionId::Export;
}

Sections::TypeEx *Sections::ExportSection::getTypeEx()
{
    return new ExportType();
}
