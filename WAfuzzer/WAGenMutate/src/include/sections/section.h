#ifndef SECTION_H
#define SECTION_H

#include <vector>
#include "context.h"
#include "data_output_stream.h"

namespace Sections
{
    enum ValType
    {
        None = 0x40,
        I32 = 0x7F,
        I64 = 0x7E,
        F32 = 0x7D,
        F64 = 0x7C,
        V128 = 0x7B,
        FuncRef = 0x70,
        ExternRef = 0x6F
    };

    static const ValType valTypes[] = {None, I32, I64, F32, F64, V128, FuncRef, ExternRef};

    using std::vector;

    class TypeEx
    {
    public:
        virtual void generate(Context *context) = 0;
        virtual void getEncode(DataOutputStream *out) = 0;
        virtual ~TypeEx(){};
    };

    class Section
    {
    private:
        int num_added;
        vector<TypeEx *> types;
        void clean();

    public:
        enum SectionId
        {
            Custom = 0,
            Type = 1,
            Import = 2,
            Function = 3,
            Table = 4,
            Memory = 5,
            Global = 6,
            Export = 7,
            Start = 8,
            Element = 9,
            Code = 10,
            Data = 11,
            DataCount = 12,
            Tag = 13,
            Module = 14,
            Instance = 15,
            Alias = 16,
        };
        Section();
        virtual SectionId id() = 0;
        virtual TypeEx *getTypeEx() = 0;
        virtual int gen_num(Context *context);
        virtual void generate(Context *context);
        virtual void getEncode(DataOutputStream *out);
        virtual ~Section();
    };
    extern vector<Section *(*)()> sections_list;
}
#endif