#ifndef EXPORT_H
#define EXPORT_H

#include "section.h"

namespace Sections
{
    class ExportType : public TypeEx
    {
    public:
        enum ItemKind
        {
            Function = 0x00,
            Table = 0x01,
            Memory = 0x02,
            Global = 0x03,
            Tag = 0x04,
            Module = 0x05,
            Instance = 0x06,
        };

    private:
        int name_len;
        char *name;
        ItemKind type;
        unsigned idx;
        bool export_start;
        void clean();

    public:
        ExportType();
        void set_export_start();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
        ~ExportType();
    };
    static const ExportType::ItemKind itemKind[] = {ExportType::Function, ExportType::Table, ExportType::Memory, ExportType::Global/*, ExportType::Tag, ExportType::Module, ExportType::Instance*/};

    class ExportSection : public Section
    {
    public:
        SectionId id();
        int gen_num(Context *context);
        TypeEx *getTypeEx();
    };
}
#endif