#include "elem_section.h"
#include "random.h"
#include "leb128.h"

static const Sections::ElemSegType::ElementMode modes[] = {Sections::ElemSegType::Passive, Sections::ElemSegType::Declared, Sections::ElemSegType::Active};
static const Sections::Elements::ElementsID elementsID[] = {Sections::Elements::FunctionsID, Sections::Elements::ExpressionsID};
static const Sections::Expressions::ElementID elementID[] = {Sections::Expressions::NullID, Sections::Expressions::FuncID};
static const Sections::ValType legal_elem_valTypes[] = {Sections::FuncRef, Sections::ExternRef};

Sections::Elements::ElementsID Sections::Functions::id()
{
    return FunctionsID;
}
void Sections::Functions::generate(Context *context)
{
    int fs_len = context->random->range(0, 0x10); // TODO
    fs.resize(fs_len);
    for (int i = 0; i < fs_len; i++)
    {
        fs[i].generate(context);
    }
}
void Sections::Functions::getEncode(DataOutputStream *out, ValType element_type)
{
    int len = fs.size();
    unsigned_to_leb128(len, out);
    for (int i = 0; i < len; i++)
    {
        fs[i].getValue(out);
    }
}

Sections::Elements::ElementsID Sections::Expressions::id()
{
    return ExpressionsID;
}
void Sections::Expressions::generate(Context *context)
{
    int e_len = context->random->range(0, 0x10); // TODO
    e.resize(e_len);
    for (int i = 0; i < e_len; i++)
    {
        e[i] = CHOICE(elementID);
    }
}
void Sections::Expressions::getEncode(DataOutputStream *out, ValType element_type)
{
    int len = e.size();
    unsigned_to_leb128(len, out);
    for (int i = 0; i < len; i++)
    {
        if (e[i] == FuncID)
        {
            out->write_byte(0xd2); // RefFunc
            unsigned_to_leb128(i, out);
        }
        else
        {
            out->write_byte(0xd0); // RefNull
            out->write_byte(element_type);
        }
        out->write_byte(0x0b); // End
    }
}

void Sections::ElemSegType::clean()
{
    if (elements)
    {
        delete elements;
        elements = nullptr;
    }
    if (offset)
    {
        delete offset;
    }
}

Sections::ElemSegType::ElemSegType()
{
    elements = nullptr;
    offset = nullptr;
}

void Sections::ElemSegType::generate(Context *context)
{
    clean();
    Elements::ElementsID esID = CHOICE(elementsID);
    if (esID == Elements::ExpressionsID)
    {
        expr_bit = 0b100;
        elements = new Expressions();
    }
    else
    {
        expr_bit = 0b000;
        elements = new Functions();
    }
    elements->generate(context);
    mode = CHOICE(modes);
    table.generate(context);
    // offset = CHOICE(Instruction::instructions)();
    offset = new Instruction::Nop();
    offset->generate(context);
    element_type = CHOICE(legal_elem_valTypes);
}

void Sections::ElemSegType::getEncode(DataOutputStream *out)
{
    if (mode == Active)
    {
        if (!table.value)
        {
            out->write_byte(0x00 | expr_bit);
            offset->getByteCode(out);
            out->write_byte(0x0b); // End
        }
        else
        {
            out->write_byte(0x02 | expr_bit);
            table.getValue(out);
            offset->getByteCode(out);
            out->write_byte(0x0b); // End
            if (expr_bit)
            {
                out->write_byte(element_type);
            }
            else
            {
                out->write_byte(0x00);
            }
        }
    }
    else if (mode == Passive)
    {
        out->write_byte(0x01 | expr_bit);
        if (expr_bit)
        {
            out->write_byte(element_type);
        }
        else
        {
            out->write_byte(0x00);
        }
    }
    else
    {
        out->write_byte(0x03 | expr_bit);
        if (expr_bit)
        {
            out->write_byte(element_type);
        }
        else
        {
            out->write_byte(0x00);
        }
    }
    elements->getEncode(out, element_type);
}

Sections::ElemSegType::~ElemSegType()
{
    clean();
}

Sections::Section::SectionId Sections::ElemSection::id()
{
    return Element;
}

Sections::TypeEx *Sections::ElemSection::getTypeEx()
{
    return new ElemSegType();
}
