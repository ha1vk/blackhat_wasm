#ifndef FUNCTION_H
#define FUNCTION_H

#include "section.h"
#include "values.h"

namespace Sections
{
    using namespace Value;
    class FunctionDefine : public TypeEx
    {
    private:
        unsigned type_index;

    public:
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };

    class FunctionSection : public Section
    {
    public:
        SectionId id();
        int gen_num(Context *context);
        TypeEx *getTypeEx();
    };
}
#endif