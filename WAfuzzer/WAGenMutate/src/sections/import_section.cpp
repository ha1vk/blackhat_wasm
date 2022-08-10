#include "import_section.h"
#include "random.h"
#include "leb128.h"
#include <assert.h>
#include <string.h>

Sections::TypeRef::TypeRefID Sections::InstanceTypeRef::id()
{
    return InstanceID;
}

void Sections::InstanceTypeRef::generate(Context *context)
{
    index.generate(context);
}

void Sections::InstanceTypeRef::getEncode(DataOutputStream *out)
{
    out->write_byte(0x00);
    index.getValue(out);
}

Sections::TypeRef::TypeRefID Sections::ModuleTypeRef::id()
{
    return ModuleID;
}

void Sections::ModuleTypeRef::generate(Context *context)
{
    index.generate(context);
}

void Sections::ModuleTypeRef::getEncode(DataOutputStream *out)
{
    out->write_byte(0x01);
    index.getValue(out);
}

Sections::TypeRef::TypeRefID Sections::FunctionTypeRef::id()
{
    return FunctionID;
}

void Sections::FunctionTypeRef::generate(Context *context)
{
    index.generate(context);
}

void Sections::FunctionTypeRef::getEncode(DataOutputStream *out)
{
    out->write_byte(0x00);
    index.getValue(out);
}

Sections::TypeRef::TypeRefID Sections::TableTypeRef::id()
{
    return TableID;
}

void Sections::TableTypeRef::generate(Context *context)
{
    ty.generate(context);
}

void Sections::TableTypeRef::getEncode(DataOutputStream *out)
{
    out->write_byte(0x01);
    ty.getEncode(out);
}

Sections::TypeRef::TypeRefID Sections::MemoryTypeRef::id()
{
    return MemoryID;
}

void Sections::MemoryTypeRef::generate(Context *context)
{
    ty.generate(context);
}

void Sections::MemoryTypeRef::getEncode(DataOutputStream *out)
{
    out->write_byte(0x02);
    ty.getEncode(out);
}

Sections::TypeRef::TypeRefID Sections::GlobalTypeRef::id()
{
    return GlobalID;
}

void Sections::GlobalTypeRef::generate(Context *context)
{
    ty.generate(context);
}

void Sections::GlobalTypeRef::getEncode(DataOutputStream *out)
{
    out->write_byte(0x03);
    ty.getEncode(out);
}

Sections::TypeRef::TypeRefID Sections::AdapterFunctionTypeRef::id()
{
    return AdapterFunctionID;
}

void Sections::AdapterFunctionTypeRef::generate(Context *context)
{
    index.generate(context);
}

void Sections::AdapterFunctionTypeRef::getEncode(DataOutputStream *out)
{
    out->write_byte(0x06);
    index.getValue(out);
}

void Sections::ImportType::clean()
{
    if (module)
    {
        free(module);
        module = nullptr;
    }
    if (name)
    {
        free(name);
        name = nullptr;
    }
    if (ty)
    {
        delete ty;
        ty = nullptr;
    }
}

Sections::ImportType::ImportType()
{
    module = nullptr;
    name = nullptr;
    ty = nullptr;
}

void Sections::ImportType::generate(Context *context)
{
    clean();
    TypeRef::TypeRefID ty_id = CHOICE(typeRefs);
    switch (ty_id)
    {
    case TypeRef::InstanceID:
        ty = new InstanceTypeRef();
        break;
    case TypeRef::ModuleID:
        ty = new ModuleTypeRef();
        break;
    case TypeRef::FunctionID:
        ty = new FunctionTypeRef();
        break;
    case TypeRef::TableID:
        ty = new TableTypeRef();
        break;
    case TypeRef::MemoryID:
        ty = new MemoryTypeRef();
        break;
    case TypeRef::GlobalID:
        ty = new GlobalTypeRef();
        break;
    case TypeRef::AdapterFunctionID:
        ty = new AdapterFunctionTypeRef();
        break;
    default:
        break;
    }
    assert(ty != nullptr);
    ty->generate(context);

    if (context->random->gbool())
    {
        module_len = context->random->range(0, 0x2000); // TODO
        module = (char *)malloc(module_len);
        for (int i = 0; i < module_len; i++)
        {
            module[i] = 'm';
        }

        name_len = context->random->range(0, 0x2000); // TODO
        name = (char *)malloc(name_len);
        for (int i = 0; i < name_len; i++)
        {
            name[i] = 'n';
        }
    }
    else // WASI Imports
    {
        string &n = CHOICE_VEC(imports_function_name);
        name = strdup(n.c_str());
        name_len = strlen(name);
        module = strdup(imports_function[n].c_str());
        module_len = strlen(module);
    }
}

void Sections::ImportType::getEncode(DataOutputStream *out)
{
    unsigned_to_leb128(module_len, out);
    for (int i = 0; i < module_len; i++)
    {
        out->write_byte(module[i]);
    }
    if (name_len != 0)
    {
        unsigned_to_leb128(name_len, out);
        for (int i = 0; i < name_len; i++)
        {
            out->write_byte(name[i]);
        }
    }
    else
    {
        out->write_byte(0x00);
        out->write_byte(0xff);
    }

    ty->getEncode(out);
}

Sections::ImportType::~ImportType()
{
    clean();
}

Sections::Section::SectionId Sections::ImportSection::id()
{
    return Import;
}

Sections::TypeEx *Sections::ImportSection::getTypeEx()
{
    return new ImportType();
}