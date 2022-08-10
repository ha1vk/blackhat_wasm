#include "table_section.h"
#include "random.h"
#include "leb128.h"
#include "config.h"

static const Sections::ValType legal_table_valTypes[] = {Sections::FuncRef, Sections::ExternRef};

void Sections::TableType::generate(Context *context)
{
    element_type = CHOICE(legal_table_valTypes);
    maximum = context->random->range(0, 0x10000);
    if (maximum && Config::strict)
    {
        minimum = context->random->range_u(0, maximum);
    }
    else
    {
        minimum = context->random->range(0, 0x10000);
    }
}
void Sections::TableType::getEncode(DataOutputStream *out)
{
    out->write_byte(element_type);
    unsigned char flag = 0;
    if (maximum)
    {
        flag |= 0b001;
    }
    out->write_byte(flag);
    unsigned_to_leb128(minimum, out);
    if (flag)
    {
        unsigned_to_leb128(maximum, out);
    }
}

Sections::Section::SectionId Sections::TableSection::id()
{
    return SectionId::Table;
}

Sections::TypeEx *Sections::TableSection::getTypeEx()
{
    return new TableType();
}