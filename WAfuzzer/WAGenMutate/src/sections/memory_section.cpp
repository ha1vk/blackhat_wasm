#include "memory_section.h"
#include "random.h"
#include "leb128.h"
#include "config.h"

void Sections::MemoryType::generate(Context *context)
{
    maximum = context->random->ushort();
    if (maximum && Config::strict)
    {
        do
        {
            minimum = context->random->ushort();
        } while (minimum > maximum);
    }
    else
    {
        minimum = context->random->ushort();
    }
    // memory64 = context->random->gbool();
}
void Sections::MemoryType::getEncode(DataOutputStream *out)
{
    unsigned char flag = 0;
    if (maximum)
    {
        flag |= 0b001;
    }
    /*if (memory64)
    {
        flag |= 0b100;
    }*/
    out->write_byte(flag);
    unsigned_to_leb128(minimum, out);
    if (maximum)
    {
        unsigned_to_leb128(maximum, out);
    }
}

Sections::Section::SectionId Sections::MemorySection::id()
{
    return SectionId::Memory;
}

Sections::TypeEx *Sections::MemorySection::getTypeEx()
{
    return new MemoryType();
}
