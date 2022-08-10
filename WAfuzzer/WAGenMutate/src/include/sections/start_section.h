#ifndef START_H
#define START_H

#include "section.h"

namespace Sections
{
    class StartSection : public Section
    {
    private:
        unsigned function_index;

    public:
        SectionId id();
        TypeEx *getTypeEx();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };
}
#endif