#include "start_section.h"
#include "random.h"
#include "leb128.h"
#include "config.h"

Sections::Section::SectionId Sections::StartSection::id()
{
    return SectionId::Start;
}

void Sections::StartSection::generate(Context *context)
{
    if (Config::verify)
    {
        function_index = 0;
    }
    else
    {
        function_index = context->random->integer();
    }
}

Sections::TypeEx *Sections::StartSection::getTypeEx()
{
    return nullptr;
}

void Sections::StartSection::getEncode(DataOutputStream *out)
{
    DataOutputStream t(0x10);
    unsigned_to_leb128(function_index, &t);
    int n = t.size();
    out->write_byte(id());      // ID
    unsigned_to_leb128(n, out); // payload Len
    out->write_from_data(&t);   // payload
}