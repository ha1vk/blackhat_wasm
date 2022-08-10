#ifndef VALUES_H
#define VALUES_H
#include <vector>
#include "context.h"
#include "section.h"
#include "data_output_stream.h"

using std::vector;

namespace Value
{
    class Value
    {
    public:
        virtual void generate(Context *context) = 0;
        virtual void getValue(DataOutputStream *code) = 0;
    };

    class byteValue : public Value
    {
    private:
        unsigned char value;

    public:
        void generate(Context *context);
        void getValue(DataOutputStream *code);
    };
    class u32Value : public Value
    {
    public:
        uint32_t value;
        void generate(Context *context);
        void getValue(DataOutputStream *code);
    };

    class u64Value : public Value
    {
    private:
        uint32_t value;

    public:
        void generate(Context *context);
        void getValue(DataOutputStream *code);
    };

    class i32Value : public Value
    {
    private:
        int32_t value;

    public:
        void generate(Context *context);
        void getValue(DataOutputStream *code);
    };

    class i64Value : public Value
    {
    private:
        int64_t value;

    public:
        void generate(Context *context);
        void getValue(DataOutputStream *code);
    };

    class i128Value : public Value
    {
    private:
        __int128_t value;

    public:
        void generate(Context *context);
        void getValue(DataOutputStream *code);
    };

    class f32Value : public Value
    {
    private:
        uint32_t value;

    public:
        void generate(Context *context);
        void getValue(DataOutputStream *code);
    };

    class f64Value : public Value
    {
    private:
        uint64_t value;

    public:
        void generate(Context *context);
        void getValue(DataOutputStream *code);
    };

    class MemValue : public Value
    {
    private:
        u32Value align;
        u32Value offset;
        u32Value memory_index;

    public:
        void generate(Context *context);
        void getValue(DataOutputStream *code);
    };
    enum BlockType
    {
        Empty = 0,
        Result = 1,
        FunctionType = 2,
    };

    class BlockValue : public Value
    {
    private:
        BlockType type;
        Sections::ValType ty;
        i32Value f;

    public:
        void generate(Context *context);
        void getValue(DataOutputStream *code);
    };
}
#endif