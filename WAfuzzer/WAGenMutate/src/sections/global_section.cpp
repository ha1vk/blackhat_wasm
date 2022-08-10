#include "global_section.h"
#include "random.h"
#include "leb128.h"

void Sections::GlobalType::generate(Context *context)
{
    val_type = CHOICE(valTypes);
    mutable_ = context->random->gbool();
}
void Sections::GlobalType::getEncode(DataOutputStream *out)
{
    out->write_byte(val_type);
    out->write_byte(mutable_);
}

void Sections::GlobalSeg::clean()
{
    if (init_expr)
    {
        delete init_expr;
        init_expr = nullptr;
    }
}

Sections::GlobalSeg::GlobalSeg()
{
    init_expr = nullptr;
}

void Sections::GlobalSeg::generate(Context *context)
{
    clean();
    global_type.generate(context);
    init_expr = CHOICE_VEC(Instruction::const_instructions)();
}
void Sections::GlobalSeg::getEncode(DataOutputStream *out)
{
    global_type.getEncode(out);
    init_expr->getByteCode(out);
    out->write_byte(0x0B); // End
}

Sections::GlobalSeg::~GlobalSeg()
{
    clean();
}

Sections::Section::SectionId Sections::GlobalSection::id()
{
    return SectionId::Global;
}

Sections::TypeEx *Sections::GlobalSection::getTypeEx()
{
    return new GlobalSeg();
}
