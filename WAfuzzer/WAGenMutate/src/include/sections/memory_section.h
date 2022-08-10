#ifndef MEMORY_SEC_H
#define MEMORY_SEC_H

#include "section.h"

namespace Sections
{
    class MemoryType : public TypeEx
    {
    private:
        uint32_t minimum;
        uint32_t maximum;
        //bool memory64;

    public:
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };
    class MemorySection : public Section
    {
    public:
        SectionId id();
        TypeEx *getTypeEx();
    };
}
#endif