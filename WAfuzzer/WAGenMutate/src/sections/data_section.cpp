#include "data_section.h"
#include "random.h"
#include "leb128.h"

void Sections::DataSegType::clean()
{
    if (offset)
    {
        delete offset;
        offset = nullptr;
    }
    if (data)
    {
        delete[] data;
        data = nullptr;
    }
}

Sections::DataSegType::DataSegType()
{
    data = nullptr;
    offset = nullptr;
}

void Sections::DataSegType::generate(Context *context)
{
    clean();
    mode = CHOICE(modes);
    memory_index.generate(context);
    offset = CHOICE_VEC(Instruction::instructions)();
    offset->generate(context);
    data_len = context->random->range(0, 0x10000);
    data = new unsigned char[data_len];
    for (int i = 0; i < data_len; i++)
    {
        data[i] = 'd';
    }
}

void Sections::DataSegType::getEncode(DataOutputStream *out)
{
    if (mode == Passive)
    {
        out->write_byte(0x01);
    }
    else
    {
        if (memory_index.value)
        {
            out->write_byte(0x02);
            memory_index.getValue(out);
            offset->getByteCode(out);
            out->write_byte(0x0b); // End
        }
        else
        {
            out->write_byte(0x00);
            offset->getByteCode(out);
            out->write_byte(0x0b); // End
        }
    }
    unsigned_to_leb128(data_len, out);
    for (int i = 0; i < data_len; i++)
    {
        out->write_byte(data[i]);
    }
}

Sections::DataSegType::~DataSegType()
{
    clean();
}

Sections::Section::SectionId Sections::DataSection::id()
{
    return Data;
}

int Sections::DataSection::gen_num(Context *context) {
    if (context->data_count == -1) {
        context->data_count = Section::gen_num(context);
    }
    return context->data_count;
}

Sections::TypeEx *Sections::DataSection::getTypeEx()
{
    return new DataSegType();
}

Sections::Section::SectionId Sections::DataCountSection::id()
{
    return DataCount;
}

Sections::TypeEx *Sections::DataCountSection::getTypeEx()
{
    return nullptr;
}

void Sections::DataCountSection::generate(Context *context)
{
    if (context->data_count != -1)
    {
        count = context->data_count; //与DataSection中的segment count保持一致
    } else {
        count = context->random->range(0,0x100); //TODO config
        context->data_count = count;
    }
}

void Sections::DataCountSection::getEncode(DataOutputStream *out)
{
    out->write_byte(id());
    DataOutputStream t(0x10);
    unsigned_to_leb128(count, &t);
    unsigned_to_leb128(t.size(), out);
    out->write_from_data(&t);
}