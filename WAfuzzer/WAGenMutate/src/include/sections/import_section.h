#ifndef IMPORT_H
#define IMPORT_H

#include "values.h"
#include "table_section.h"
#include "memory_section.h"
#include "global_section.h"
#include <map>

namespace Sections
{
    using namespace Value;
    using std::map;

    class TypeRef
    {
    public:
        enum TypeRefID
        {
            /// The definition is an instance.
            ///
            /// The value is an index in the types index space.
            /// The index must be to an instance type.
            InstanceID,
            /// The definition is a module.
            ///
            /// The value is an index in the types index space.
            /// The index must be to a module type.
            ModuleID,
            /// The definition is a core wasm function.
            ///
            /// The value is an index in the types index space.
            /// The index must be to a function type.
            FunctionID,
            /// The definition is a core wasm table.
            TableID,
            /// The definition is a core wasm memory.
            MemoryID,
            /// The definition is a core wasm global.
            GlobalID,
            /// The definition is an adapter function.
            ///
            /// The value is an index in the types index space.
            /// The index must be to an adapter function type.
            AdapterFunctionID,
        };
        virtual TypeRefID id() = 0;
        virtual void generate(Context *context) = 0;
        virtual void getEncode(DataOutputStream *out) = 0;
        virtual ~TypeRef() {}
    };

    static const TypeRef::TypeRefID typeRefs[] = {/*TypeRef::InstanceID, TypeRef::ModuleID, */ TypeRef::FunctionID, TypeRef::TableID, TypeRef::MemoryID, TypeRef::GlobalID /*, TypeRef::AdapterFunctionID*/};

    class InstanceTypeRef : public TypeRef
    {
    private:
        u32Value index;

    public:
        TypeRefID id();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };
    class ModuleTypeRef : public TypeRef
    {
    private:
        u32Value index;

    public:
        TypeRefID id();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };
    class FunctionTypeRef : public TypeRef
    {
    private:
        u32Value index;

    public:
        TypeRefID id();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };
    class TableTypeRef : public TypeRef
    {
    private:
        TableType ty;

    public:
        TypeRefID id();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };
    class MemoryTypeRef : public TypeRef
    {
    private:
        MemoryType ty;

    public:
        TypeRefID id();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };
    class GlobalTypeRef : public TypeRef
    {
    private:
        GlobalType ty;

    public:
        TypeRefID id();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };
    class AdapterFunctionTypeRef : public TypeRef
    {
    private:
        u32Value index;

    public:
        TypeRefID id();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
    };

    extern map<string, string> imports_function;
    extern vector<string> imports_function_name;

    class ImportType : public TypeEx
    {
    private:
        TypeRef *ty;
        char *module;
        int module_len;
        char *name;
        int name_len;
        void clean();

    public:
        ImportType();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
        ~ImportType();
    };

    class ImportSection : public Section
    {
    public:
        SectionId id();
        TypeEx *getTypeEx();
    };
}
#endif