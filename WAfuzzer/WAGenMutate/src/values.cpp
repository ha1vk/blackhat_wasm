#include "values.h"
#include "random.h"
#include "leb128.h"
#include "config.h"

void Value::byteValue::generate(Context *context)
{
    value = (char)context->random->range(0, 255);
};

void Value::byteValue::getValue(DataOutputStream *code)
{
    code->write_byte(value);
};

void Value::u32Value::generate(Context *context)
{
    value = context->random->integer();
};

void Value::u32Value::getValue(DataOutputStream *code)
{
    unsigned_to_leb128(value, code);
};

void Value::u64Value::generate(Context *context)
{
    value = context->random->integer64();
};

void Value::u64Value::getValue(DataOutputStream *code)
{
    unsigned_to_leb128(value, code);
};

void Value::i32Value::generate(Context *context)
{
    value = context->random->integer();
};

void Value::i32Value::getValue(DataOutputStream *code)
{
    signed_to_leb128(value, code);
};

void Value::i64Value::generate(Context *context)
{
    value = context->random->integer64();
};

void Value::i64Value::getValue(DataOutputStream *code)
{
    signed_to_leb128(value, code);
};

void Value::i128Value::generate(Context *context)
{
    value = context->random->integer128();
};

void Value::i128Value::getValue(DataOutputStream *code)
{
    unsigned char *p = (unsigned char *)&value;
    code->write_buf(p, 0x10);
};

void Value::f32Value::generate(Context *context)
{
    value = context->random->float32();
};

void Value::f32Value::getValue(DataOutputStream *code)
{
    code->write_uint(value);
};

void Value::f64Value::generate(Context *context)
{
    value = context->random->float64();
};

void Value::f64Value::getValue(DataOutputStream *code)
{
    code->write_ulong(value);
};

void Value::MemValue::generate(Context *context)
{
    memory_index.generate(context);
    align.generate(context);
    offset.generate(context);
};

void Value::MemValue::getValue(DataOutputStream *code)
{
    if (Config::enable_multi_memory && align.value >= 64)
    {
        unsigned_to_leb128(align.value | (1 << 6), code);
        offset.getValue(code);
        memory_index.getValue(code);
    }
    else
    {
        align.getValue(code);
        offset.getValue(code);
    }
};

void Value::BlockValue::generate(Context *context)
{
    type = (BlockType)context->random->selector(3);
    switch (type)
    {
    case Result:
        ty = CHOICE(Sections::valTypes);
        break;
    case FunctionType:
        f.generate(context);
    default:
        break;
    }
};

void Value::BlockValue::getValue(DataOutputStream *code)
{
    switch (type)
    {
    case Empty:
        code->write_byte(0x40);
        break;
    case Result:
        code->write_byte(ty);
        break;
    case FunctionType:
        f.getValue(code);
        break;
    default:
        break;
    }
};