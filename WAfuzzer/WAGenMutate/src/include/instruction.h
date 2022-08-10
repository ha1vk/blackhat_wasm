#ifndef INSTRUCTION_H
#define INSTRUCTION_H

#include "values.h"
#include "context.h"
#include "section.h"

namespace Instruction
{
    using namespace Value;

    class Instruction
    {
    public:
        virtual void generate(Context *context) = 0;
        virtual void getByteCode(DataOutputStream *code) = 0;
        virtual ~Instruction() {}
    };

    class Unreachable : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class Nop : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class Block : public Instruction
    {
    private:
        BlockValue bt;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class Loop : public Instruction
    {
    private:
        BlockValue bt;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class If : public Instruction
    {
    private:
        BlockValue bt;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class Else : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class Try : public Instruction
    {
    private:
        BlockValue bt;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class Delegate : public Instruction
    {
    private:
        u32Value l;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class Catch : public Instruction
    {
    private:
        u32Value t;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class CatchAll : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class End : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class Br : public Instruction
    {
    private:
        u32Value l;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class BrIf : public Instruction
    {
    private:
        u32Value l;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class BrTable : public Instruction
    {
    private:
        vector<u32Value> ls;
        u32Value l;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class Return : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class Call : public Instruction
    {
    private:
        int from_where; //从哪个函数去调用的
        u32Value f;

    public:
        void generate(Context *context);
        void set_from(int from_where);
        void getByteCode(DataOutputStream *code);
    };

    class CallIndirect : public Instruction
    {
    private:
        u32Value ty;
        u32Value table;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class Throw : public Instruction
    {
    private:
        u32Value t;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class Rethrow : public Instruction
    {
    private:
        u32Value l;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    // Parametric instructions.
    class Drop : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class Select : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    // Variable instructions.
    class LocalGet : public Instruction
    {
    private:
        u32Value value;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class LocalSet : public Instruction
    {
    private:
        u32Value value;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class LocalTee : public Instruction
    {
    private:
        u32Value value;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class GlobalGet : public Instruction
    {
    private:
        u32Value value;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class GlobalSet : public Instruction
    {
    private:
        u32Value value;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    // Memory instructions.
    class I32Load : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Load : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F32Load : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Load : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Load8_S : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32Load8_U : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Load16_S : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32Load16_U : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Load8_S : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Load8_U : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Load16_S : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Load16_U : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Load32_S : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Load32_U : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Store : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Store : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Store : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F64Store : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Store8 : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Store16 : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Store8 : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Store16 : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Store32 : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class MemorySize : public Instruction
    {
    private:
        u32Value value;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class MemoryGrow : public Instruction
    {
    private:
        u32Value value;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class MemoryInit : public Instruction
    {
    private:
        u32Value mem;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class DataDrop : public Instruction
    {
    private:
        u32Value data;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class MemoryCopy : public Instruction
    {
    private:
        u32Value dst;
        u32Value src;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class MemoryFill : public Instruction
    {
    private:
        u32Value mem;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    // Numeric instructions.
    class I32Const : public Instruction
    {
    private:
        i32Value value;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Const : public Instruction
    {
    private:
        i64Value value;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F32Const : public Instruction
    {
    private:
        f32Value value;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F64Const : public Instruction
    {
    private:
        f64Value value;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Eqz : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Eq : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Ne : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32LtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32LtU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32GtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32GtU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32LeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32LeU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32GeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32GeU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Eqz : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Eq : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Ne : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64LtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64LtU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64GtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64GtU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64LeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64LeU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64GeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64GeU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F32Eq : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F32Ne : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Lt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Gt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F32Le : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F32Ge : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F64Eq : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F64Ne : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F64Lt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F64Gt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F64Le : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class F64Ge : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Clz : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32Ctz : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Popcnt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Add : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Sub : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Mul : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32DivS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32DivU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32RemS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32RemU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32And : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Or : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Xor : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Shl : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32ShrS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32ShrU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Rotl : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I32Rotr : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Clz : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Ctz : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Popcnt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Add : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Sub : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64Mul : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64DivS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64DivU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64RemS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class I64RemU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64And : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Or : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Xor : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Shl : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64ShrS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64ShrU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Rotl : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Rotr : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Abs : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Neg : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Ceil : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Floor : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Trunc : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Nearest : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Sqrt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Add : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Sub : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Mul : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Div : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Min : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Max : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32Copysign : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Abs : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Neg : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Ceil : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Floor : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Trunc : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Nearest : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Sqrt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Add : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Sub : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Mul : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Div : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Min : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Max : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64Copysign : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32WrapI64 : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32TruncF32S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32TruncF32U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32TruncF64S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32TruncF64U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64ExtendI32S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64ExtendI32U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64TruncF32S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64TruncF32U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64TruncF64S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64TruncF64U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32ConvertI32S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32ConvertI32U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32ConvertI64S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32ConvertI64U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32DemoteF64 : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64ConvertI32S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64ConvertI32U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64ConvertI64S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64ConvertI64U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64PromoteF32 : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32ReinterpretF32 : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64ReinterpretF64 : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32ReinterpretI32 : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64ReinterpretI64 : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32Extend8S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32Extend16S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Extend8S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Extend16S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64Extend32S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32TruncSatF32S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32TruncSatF32U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32TruncSatF64S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32TruncSatF64U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64TruncSatF32S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64TruncSatF32U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64TruncSatF64S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64TruncSatF64U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    // Reference types instructions.
    class TypedSelect : public Instruction
    {
    private:
        Sections::ValType ty;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class RefNull : public Instruction
    {
    private:
        Sections::ValType ty;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class RefIsNull : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class RefFunc : public Instruction
    {
    private:
        u32Value f;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    // Bulk memory instructions.
    class TableInit : public Instruction
    {
    private:
        u32Value segment;
        u32Value table;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class ElemDrop : public Instruction
    {
    private:
        u32Value segment;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class TableFill : public Instruction
    {
    private:
        u32Value table;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class TableSet : public Instruction
    {
    private:
        u32Value table;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class TableGet : public Instruction
    {
    private:
        u32Value table;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class TableGrow : public Instruction
    {
    private:
        u32Value table;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class TableSize : public Instruction
    {
    private:
        u32Value table;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class TableCopy : public Instruction
    {
    private:
        u32Value dst;
        u32Value src;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    // SIMD instructions.
    class V128Load : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load8x8S : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load8x8U : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load16x4S : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load16x4U : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load32x2S : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load32x2U : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load8Splat : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load16Splat : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load32Splat : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load64Splat : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load32Zero : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load64Zero : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Store : public Instruction
    {
    private:
        MemValue memarg;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load8Lane : public Instruction
    {
    private:
        MemValue memarg;
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class V128Load16Lane : public Instruction
    {
    private:
        MemValue memarg;
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Load32Lane : public Instruction
    {
    private:
        MemValue memarg;
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class V128Load64Lane : public Instruction
    {
    private:
        MemValue memarg;
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class V128Store8Lane : public Instruction
    {
    private:
        MemValue memarg;
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Store16Lane : public Instruction
    {
    private:
        MemValue memarg;
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Store32Lane : public Instruction
    {
    private:
        MemValue memarg;
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Store64Lane : public Instruction
    {
    private:
        MemValue memarg;
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    class V128Const : public Instruction
    {
    private:
        i128Value x;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Shuffle : public Instruction
    {
    private:
        byteValue lanes[16];

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16ExtractLaneS : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16ExtractLaneU : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16ReplaceLane : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtractLaneS : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtractLaneU : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ReplaceLane : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ExtractLane : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ReplaceLane : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ExtractLane : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ReplaceLane : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4ExtractLane : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4ReplaceLane : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2ExtractLane : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2ReplaceLane : public Instruction
    {
    private:
        byteValue lane;

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Swizzle : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Splat : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8Splat : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4Splat : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2Splat : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Splat : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Splat : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Eq : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Ne : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16LtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16LtU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16GtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16GtU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16LeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16LeU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16GeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16GeU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8Eq : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8Ne : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8LtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8LtU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8GtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8GtU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8LeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8LeU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8GeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8GeU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4Eq : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4Ne : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4LtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4LtU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4GtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4GtU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4LeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4LeU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4GeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4GeU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2Eq : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2Ne : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2LtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2GtS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2LeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2GeS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Eq : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Ne : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Lt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Gt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Le : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Ge : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Eq : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Ne : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Lt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Gt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Le : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Ge : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Not : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128And : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128AndNot : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Or : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Xor : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128Bitselect : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class V128AnyTrue : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Abs : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Neg : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Popcnt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16AllTrue : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Bitmask : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16NarrowI16x8S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16NarrowI16x8U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Shl : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16ShrS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16ShrU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Add : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16AddSatS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16AddSatU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16Sub : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16SubSatS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16SubSatU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16MinS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16MinU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16MaxS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16MaxU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16RoundingAverageU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtAddPairwiseI8x16S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtAddPairwiseI8x16U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8Abs : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8Neg : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8Q15MulrSatS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8AllTrue : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8Bitmask : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8NarrowI32x4S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8NarrowI32x4U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtendLowI8x16S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtendHighI8x16S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtendLowI8x16U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtendHighI8x16U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8Shl : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ShrS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ShrU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8Add : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8AddSatS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8AddSatU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8Sub : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8SubSatS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8SubSatU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8Mul : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8MinS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8MinU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8MaxS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8MaxU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8RoundingAverageU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtMulLowI8x16S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtMulHighI8x16S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtMulLowI8x16U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8ExtMulHighI8x16U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ExtAddPairwiseI16x8S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ExtAddPairwiseI16x8U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4Abs : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4Neg : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4AllTrue : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4Bitmask : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ExtendLowI16x8S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ExtendHighI16x8S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ExtendLowI16x8U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ExtendHighI16x8U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4Shl : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ShrS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ShrU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4Add : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4Sub : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4Mul : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4MinS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4MinU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4MaxS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4MaxU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4DotI16x8S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ExtMulLowI16x8S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ExtMulHighI16x8S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ExtMulLowI16x8U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4ExtMulHighI16x8U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2Abs : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2Neg : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2AllTrue : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2Bitmask : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ExtendLowI32x4S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ExtendHighI32x4S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ExtendLowI32x4U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ExtendHighI32x4U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2Shl : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ShrS : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ShrU : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2Add : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2Sub : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2Mul : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ExtMulLowI32x4S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ExtMulHighI32x4S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ExtMulLowI32x4U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2ExtMulHighI32x4U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Ceil : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Floor : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Trunc : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Nearest : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Abs : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Neg : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Sqrt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Add : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Sub : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Mul : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Div : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Min : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Max : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4PMin : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4PMax : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Ceil : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Floor : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Trunc : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Nearest : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Abs : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Neg : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Sqrt : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Add : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Sub : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Mul : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Div : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Min : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Max : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2PMin : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2PMax : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4TruncSatF32x4S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4TruncSatF32x4U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4ConvertI32x4S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4ConvertI32x4U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4TruncSatF64x2SZero : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4TruncSatF64x2UZero : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2ConvertLowI32x4S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2ConvertLowI32x4U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4DemoteF64x2Zero : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2PromoteLowF32x4 : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16RelaxedSwizzle : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4RelaxedTruncSatF32x4S : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4RelaxedTruncSatF32x4U : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4RelaxedTruncSatF64x2SZero : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4RelaxedTruncSatF64x2UZero : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Fma : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4Fms : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Fma : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2Fms : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I8x16LaneSelect : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I16x8LaneSelect : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I32x4LaneSelect : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class I64x2LaneSelect : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4RelaxedMin : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F32x4RelaxedMax : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2RelaxedMin : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };
    class F64x2RelaxedMax : public Instruction
    {
    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
    };

    extern vector<Instruction *(*)(void)> block_instructions;
    extern vector<Instruction *(*)(void)> instructions;
    extern vector<Instruction *(*)(void)> const_instructions;

    class IfStateMent : public Instruction
    {
    private:
        If if_s;
        vector<Instruction *> if_instructions;
        End end;
        void clean();

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
        ~IfStateMent();
    };
    class IfElseStateMent : public Instruction
    {
    private:
        If if_s;
        vector<Instruction *> if_instructions;
        Else else_s;
        vector<Instruction *> else_instructions;
        End end;
        void clean();

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
        ~IfElseStateMent();
    };
    class LoopStateMent : public Instruction
    {
    private:
        Loop loop;
        vector<Instruction *> loop_instructions;
        End end;
        void clean();

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
        ~LoopStateMent();
    };
    class BlockStateMent : public Instruction
    {
    private:
        Block block;
        vector<Instruction *> block_instructions;
        End end;
        void clean();

    public:
        void generate(Context *context);
        void getByteCode(DataOutputStream *code);
        ~BlockStateMent();
    };
}
#endif