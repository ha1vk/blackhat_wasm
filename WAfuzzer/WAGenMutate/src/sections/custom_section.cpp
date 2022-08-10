#include "custom_section.h"
#include "random.h"
#include "leb128.h"

void Sections::CustomSection::clean()
{
    if (name)
    {
        delete[] name;
        name = nullptr;
    }
    if (data)
    {
        delete[] data;
        data = nullptr;
    }
}

Sections::CustomSection::CustomSection()
{
    name = nullptr;
    name_len = 0;
    data = nullptr;
    data_len = 0;
}

Sections::Section::SectionId Sections::CustomSection::id()
{
    return Custom;
}

Sections::TypeEx *Sections::CustomSection::getTypeEx()
{
    return nullptr;
}

void Sections::CustomSection::generate(Context *context)
{
    clean();
    name_len = context->random->range(0, 0x20000);
    name = new char[name_len];
    for (int i = 0; i < name_len; i++)
    {
        name[i] = 'a';
    }
    data_len = context->random->range(0, 0x20000);
    data = new char[data_len];
    for (int i = 0; i < data_len; i++)
    {
        data[i] = 'a';
    }
}

void Sections::CustomSection::getEncode(DataOutputStream *out)
{
    DataOutputStream t(0x10);
    unsigned_to_leb128(name_len, &t);
    int n = t.size();
    out->write_byte(id());                            // ID
    unsigned_to_leb128(n + name_len + data_len, out); // Payload Len
    out->write_from_data(&t);                         // name_len
    out->write_buf(name, name_len);                   // name
    out->write_buf(data, data_len);                   // data
}

Sections::CustomSection::~CustomSection()
{
    clean();
}