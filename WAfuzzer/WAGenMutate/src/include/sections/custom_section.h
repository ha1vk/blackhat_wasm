#ifndef CUSTOM_H
#define CUSTOM_H

#include "section.h"

namespace Sections
{
    class CustomSection : public Section
    {
    private:
        char *name;
        int name_len;
        char *data;
        int data_len;
        void clean();

    public:
        CustomSection();
        SectionId id();
        TypeEx *getTypeEx();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
        ~CustomSection();
    };
}
#endif