#ifndef CODE_H
#define CODE_H

#include "section.h"
#include "instruction.h"

namespace Sections
{
    class FunctionCode : public TypeEx
    {
    private:
        vector<ValType> locals;
        vector<Instruction::Instruction *> code_instructions;
        int my_index;
        void clean();

    public:
        FunctionCode();
        void set_index(int index);
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
        ~FunctionCode();
    };
    class CodeSection : public Section
    {
    public:
        SectionId id();
        int gen_num(Context *context);
        TypeEx *getTypeEx();
    };
}
#endif