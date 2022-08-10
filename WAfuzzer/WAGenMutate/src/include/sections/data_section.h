#ifndef DATA_H
#define DATA_H

#include "section.h"
#include "values.h"
#include "instruction.h"

namespace Sections
{
    using namespace Value;

    class DataSegType : public TypeEx
    {
    public:
        enum DataSegmentMode
        {
            /// An active data segment.
            Active,
            /// Passive data segments are part of the bulk memory proposal.
            Passive,
        };

    private:
        DataSegmentMode mode;
        u32Value memory_index;
        Instruction::Instruction *offset;
        unsigned char *data;
        unsigned data_len;
        void clean();

    public:
        DataSegType();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
        ~DataSegType();
    };

    static const DataSegType::DataSegmentMode modes[] = {DataSegType::Active, DataSegType::Passive};

    class DataSection : public Section
    {
    public:
        SectionId id();
        int gen_num(Context *context);
        TypeEx *getTypeEx();
    };

    class DataCountSection : public Section
    {
    private:
        unsigned count;

    public:
        SectionId id();
        TypeEx *getTypeEx();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };
}
#endif