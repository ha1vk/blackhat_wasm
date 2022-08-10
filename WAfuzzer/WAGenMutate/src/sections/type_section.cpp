#include "type_section.h"
#include "random.h"
#include "leb128.h"

void Sections::FunctionType::clean()
{
    if (params_types)
    {
        delete[] params_types;
        params_types = nullptr;
    }
    if (results_types)
    {
        delete[] results_types;
        results_types = nullptr;
    }
}

Sections::FunctionType::FunctionType()
{
    params_len = 0;
    params_types = nullptr;
    results_len = 0;
    results_types = nullptr;
    start_function_type = false;
}

void Sections::FunctionType::set_start_function()
{
    start_function_type = true;
}

void Sections::FunctionType::generate(Context *context)
{
    clean();
    if (!start_function_type)
        params_len = context->random->range(0, 0x10000); // TODO config
    else
        params_len = 0;
    params_types = new char[params_len];
    for (int i = 0; i < params_len; i++)
    {
        params_types[i] = CHOICE(valTypes);
    }
    if (!start_function_type)
        results_len = context->random->range(0, 0x10000); // TODO config
    else
        results_len = 0;
    results_types = new char[results_len];
    for (int i = 0; i < results_len; i++)
    {
        results_types[i] = CHOICE(valTypes);
    }
}

void Sections::FunctionType::getEncode(DataOutputStream *out)
{
    out->write_byte(0x60);
    unsigned_to_leb128(params_len, out);
    out->write_buf(params_types, params_len);
    unsigned_to_leb128(results_len, out);
    out->write_buf(results_types, results_len);
}

Sections::FunctionType::~FunctionType()
{
    clean();
}

Sections::Section::SectionId Sections::TypeSection::id()
{
    return Type;
}

int Sections::TypeSection::gen_num(Context *context)
{
    if (context->type_count == -1)
    {
        context->type_count = Section::gen_num(context);
    }
    return context->type_count;
}

Sections::TypeEx *Sections::TypeSection::getTypeEx()
{
    return new FunctionType();
}