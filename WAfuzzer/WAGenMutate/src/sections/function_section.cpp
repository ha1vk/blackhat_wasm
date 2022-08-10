#include "function_section.h"
#include "random.h"
#include "leb128.h"

void Sections::FunctionDefine::generate(Context *context)
{
    if (context->type_count == -1)
    {
        context->type_count = context->random->range(0, 0x100); // TODO config
    }
    if (context->type_count == 0)
    {
        type_index = 0;
    }
    else
    {
        type_index = context->random->selector(context->type_count);
    }
}

void Sections::FunctionDefine::getEncode(DataOutputStream *out)
{
    unsigned_to_leb128(type_index, out);
}

int Sections::FunctionSection::gen_num(Context *context) {
    if (context->code_count == -1) {
        context->code_count = context->random->range(1, 0x10); //TODO 
    }
    return context->code_count;
}

Sections::Section::SectionId Sections::FunctionSection::id()
{
    return Function;
}

Sections::TypeEx *Sections::FunctionSection::getTypeEx()
{
    return new FunctionDefine();
}
