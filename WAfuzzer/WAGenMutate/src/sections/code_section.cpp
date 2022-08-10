#include "code_section.h"
#include "random.h"
#include "leb128.h"

void Sections::FunctionCode::clean()
{
    int len = code_instructions.size();
    if (len)
    {
        for (int i = 0; i < len; i++)
        {
            delete code_instructions[i];
        }
        code_instructions.clear();
    }
}

Sections::FunctionCode::FunctionCode()
{
    my_index = 0;
}

void Sections::FunctionCode::set_index(int index) {
    my_index = index;
}

void Sections::FunctionCode::generate(Context *context)
{
    clean();
    int locals_count = context->random->range(0, 0x10); // TODO
    for (int i = 0; i < locals_count; i++)
    {
        locals.push_back(CHOICE(valTypes));
    }
    int num_instruction = context->random->range(0, 0x10); // TODO
    for (int i = 0; i < num_instruction; i++)
    {
        Instruction::Instruction *ins = CHOICE_VEC(Instruction::instructions)();
        Instruction::Call *call = dynamic_cast<Instruction::Call *>(ins);
        if (call != nullptr) // call instance
        {
            call->set_from(my_index);
        }
        ins->generate(context);
        code_instructions.push_back(ins);
    }
    code_instructions.push_back(new Instruction::End());
}

void Sections::FunctionCode::getEncode(DataOutputStream *out)
{
    DataOutputStream t(0x1000);
    int locals_num = locals.size();
    unsigned_to_leb128(locals_num, &t);
    for (int i = 0; i < locals_num; i++)
    {
        unsigned_to_leb128(i, &t);
        t.write_byte(locals[i]);
    }
    int code_ins_len = code_instructions.size();
    for (int i = 0; i < code_ins_len; i++)
    {
        code_instructions[i]->getByteCode(&t);
    }
    unsigned_to_leb128(t.size(), out);
    out->write_from_data(&t);
}

Sections::FunctionCode::~FunctionCode()
{
    clean();
}

Sections::Section::SectionId Sections::CodeSection::id()
{
    return Code;
}

int Sections::CodeSection::gen_num(Context *context)
{
    if (context->code_count == -1)
    {
        context->code_count = context->random->range(1, 0x10); // at least one
    }
    return context->code_count;
}

Sections::TypeEx *Sections::CodeSection::getTypeEx()
{
    return new FunctionCode;
}