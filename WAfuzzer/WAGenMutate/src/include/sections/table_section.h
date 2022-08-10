#ifndef TABLE_H
#define TABLE_H

#include "section.h"

namespace Sections
{
    class TableType : public TypeEx
    {
    private:
        ValType element_type;
        unsigned minimum;
        unsigned maximum;

    public:
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };
    class TableSection : public Section
    {
    public:
        SectionId id();
        TypeEx *getTypeEx();
    };
}
#endif