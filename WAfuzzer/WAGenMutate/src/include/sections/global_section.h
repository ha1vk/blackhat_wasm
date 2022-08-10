#ifndef GLOBAL_H
#define GLOBAL_H

#include "section.h"
#include "instruction.h"

namespace Sections
{
    class GlobalType : public TypeEx
    {
    private:
        ValType val_type;
        bool mutable_;

    public:
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };

    class GlobalSeg : public TypeEx
    {
        GlobalType global_type;
        Instruction::Instruction *init_expr;
        void clean();

    public:
        GlobalSeg();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
        ~GlobalSeg();
    };

    class GlobalSection : public Section
    {
    public:
        SectionId id();
        TypeEx *getTypeEx();
    };
}
#endif