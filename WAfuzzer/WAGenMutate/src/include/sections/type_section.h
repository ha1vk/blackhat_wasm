#ifndef TYPE_H
#define TYPE_H

#include "section.h"

namespace Sections
{
    class FunctionType : public TypeEx
    {
    private:
        int params_len;
        char *params_types;
        int results_len;
        char *results_types;
        bool start_function_type;
        void clean();

    public:
        FunctionType();
        void set_start_function();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
        ~FunctionType();
    };

    /*class Module : public TypeEx
    {
    private:
    public:
        Module();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
        ~Module();
    };*/
    class TypeSection : public Section
    {
    public:
        SectionId id();
        int gen_num(Context *context);
        TypeEx *getTypeEx();
    };
}
#endif