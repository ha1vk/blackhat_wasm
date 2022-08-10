
#include "instruction.h"
#include "leb128.h"
#include "random.h"

void Instruction::Unreachable::generate(Context *context)
{
}

void Instruction::Unreachable::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x00);
}

void Instruction::Nop::generate(Context *context)
{
}

void Instruction::Nop::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x01);
}

void Instruction::Block::generate(Context *context)
{
    bt.generate(context);
}

void Instruction::Block::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x02);
    bt.getValue(code);
}

void Instruction::Loop::generate(Context *context)
{
    bt.generate(context);
}

void Instruction::Loop::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x03);
    bt.getValue(code);
}

void Instruction::If::generate(Context *context)
{
    bt.generate(context);
}
void Instruction::If::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x04);
    bt.getValue(code);
}
void Instruction::Else::generate(Context *context)
{
}
void Instruction::Else::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x05);
}
void Instruction::Try::generate(Context *context)
{
    bt.generate(context);
}
void Instruction::Try::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x06);
    bt.getValue(code);
}
void Instruction::Delegate::generate(Context *context)
{
    l.generate(context);
}
void Instruction::Delegate::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x18);
    l.getValue(code);
}
void Instruction::Catch::generate(Context *context)
{
    t.generate(context);
}
void Instruction::Catch::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x07);
    t.getValue(code);
}
void Instruction::CatchAll::generate(Context *context)
{
}
void Instruction::CatchAll::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x19);
}
void Instruction::End::generate(Context *context)
{
}
void Instruction::End::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x0b);
}
void Instruction::Br::generate(Context *context)
{
    l.generate(context);
}
void Instruction::Br::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x0c);
    l.getValue(code);
}
void Instruction::BrIf::generate(Context *context)
{
    l.generate(context);
}
void Instruction::BrIf::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x0d);
    l.getValue(code);
}
void Instruction::BrTable::generate(Context *context)
{
    int len = context->random->range(0, 0x1000);
    ls.resize(len);
    for (int i = 0; i < len; i++)
    {
        ls[i].generate(context);
    }
    l.generate(context);
}
void Instruction::BrTable::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x0e);
    int len = ls.size();
    unsigned_to_leb128(len, code);
    for (int i = 0; i < len; i++)
    {
        ls[i].getValue(code);
    }
    l.getValue(code);
}
void Instruction::Return::generate(Context *context)
{
}
void Instruction::Return::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x0f);
}
void Instruction::Call::generate(Context *context)
{
    f.generate(context);
    while (context->check_loop(from_where, f.value))
    { //避免call形成死循环
        f.value++;
    }
    context->add_cfg(from_where, f.value);
}

void Instruction::Call::set_from(int from_where)
{
    this->from_where = from_where;
}

void Instruction::Call::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x10);
    f.getValue(code);
}
void Instruction::CallIndirect::generate(Context *context)
{
    ty.generate(context);
    table.generate(context);
}
void Instruction::CallIndirect::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x11);
    ty.getValue(code);
    table.getValue(code);
}
void Instruction::Throw::generate(Context *context)
{
    t.generate(context);
}
void Instruction::Throw::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x08);
    t.getValue(code);
}
void Instruction::Rethrow::generate(Context *context)
{
    l.generate(context);
}
void Instruction::Rethrow::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x09);
    l.getValue(code);
}
// Parametric instructions.
void Instruction::Drop::generate(Context *context)
{
}
void Instruction::Drop::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x1a);
}
void Instruction::Select::generate(Context *context)
{
}
void Instruction::Select::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x1b);
}

// Variable instructions.
void Instruction::LocalGet::generate(Context *context)
{
    value.generate(context);
}

void Instruction::LocalGet::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x20);
    value.getValue(code);
}

void Instruction::LocalSet::generate(Context *context)
{
    value.generate(context);
}

void Instruction::LocalSet::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x21);
    value.getValue(code);
}

void Instruction::LocalTee::generate(Context *context)
{
    value.generate(context);
}

void Instruction::LocalTee::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x22);
    value.getValue(code);
}

void Instruction::GlobalGet::generate(Context *context)
{
    value.generate(context);
}

void Instruction::GlobalGet::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x23);
    value.getValue(code);
}

void Instruction::GlobalSet::generate(Context *context)
{
    value.generate(context);
}

void Instruction::GlobalSet::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x24);
    value.getValue(code);
}

// Memory instructions.
void Instruction::I32Load::generate(Context *context)
{
    memarg.generate(context);
}

void Instruction::I32Load::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x28);
    memarg.getValue(code);
}

void Instruction::I64Load::generate(Context *context)
{
    memarg.generate(context);
}

void Instruction::I64Load::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x29);
    memarg.getValue(code);
}

void Instruction::F32Load::generate(Context *context)
{
    memarg.generate(context);
}

void Instruction::F32Load::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x2A);
    memarg.getValue(code);
}

void Instruction::F64Load::generate(Context *context)
{
    memarg.generate(context);
}

void Instruction::F64Load::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x2B);
    memarg.getValue(code);
}

void Instruction::I32Load8_S::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I32Load8_S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x2C);
    memarg.getValue(code);
}

void Instruction::I32Load8_U::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I32Load8_U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x2D);
    memarg.getValue(code);
}
void Instruction::I32Load16_S::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I32Load16_S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x2E);
    memarg.getValue(code);
}

void Instruction::I32Load16_U::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I32Load16_U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x2F);
    memarg.getValue(code);
}
void Instruction::I64Load8_S::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I64Load8_S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x30);
    memarg.getValue(code);
}

void Instruction::I64Load8_U::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I64Load8_U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x31);
    memarg.getValue(code);
}
void Instruction::I64Load16_S::generate(Context *context)
{
    memarg.generate(context);
}

void Instruction::I64Load16_S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x32);
    memarg.getValue(code);
}
void Instruction::I64Load16_U::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I64Load16_U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x33);
    memarg.getValue(code);
}
void Instruction::I64Load32_S::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I64Load32_S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x34);
    memarg.getValue(code);
}

void Instruction::I64Load32_U::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I64Load32_U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x35);
    memarg.getValue(code);
}
void Instruction::I32Store::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I32Store::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x36);
    memarg.getValue(code);
}
void Instruction::I64Store::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I64Store::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x37);
    memarg.getValue(code);
}
void Instruction::F32Store::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::F32Store::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x38);
    memarg.getValue(code);
}
void Instruction::F64Store::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::F64Store::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x39);
    memarg.getValue(code);
}
void Instruction::I32Store8::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I32Store8::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x3A);
    memarg.getValue(code);
}
void Instruction::I32Store16::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I32Store16::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x3B);
    memarg.getValue(code);
}
void Instruction::I64Store8::generate(Context *context)
{
}
void Instruction::I64Store8::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x3C);
    memarg.getValue(code);
}
void Instruction::I64Store16::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I64Store16::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x3D);
    memarg.getValue(code);
}

void Instruction::I64Store32::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::I64Store32::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x3E);
    memarg.getValue(code);
}
void Instruction::MemorySize::generate(Context *context)
{
    value.generate(context);
}
void Instruction::MemorySize::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x3F);
    value.getValue(code);
}
void Instruction::MemoryGrow::generate(Context *context)
{
    value.generate(context);
}
void Instruction::MemoryGrow::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x40);
    value.getValue(code);
}
void Instruction::MemoryInit::generate(Context *context)
{
    mem.generate(context);
}
void Instruction::MemoryInit::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(0x8, code);
    mem.getValue(code);
}
void Instruction::DataDrop::generate(Context *context)
{
    data.generate(context);
}
void Instruction::DataDrop::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(0x9, code);
    data.getValue(code);
}
void Instruction::MemoryCopy::generate(Context *context)
{
    dst.generate(context);
    src.generate(context);
}
void Instruction::MemoryCopy::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(10, code);
    dst.getValue(code);
    src.getValue(code);
}
void Instruction::MemoryFill::generate(Context *context)
{
    mem.generate(context);
}
void Instruction::MemoryFill::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(11, code);
    mem.getValue(code);
}
// Numeric instructions.
void Instruction::I32Const::generate(Context *context)
{
    value.generate(context);
}
void Instruction::I32Const::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x41);
    value.getValue(code);
}
void Instruction::I64Const::generate(Context *context)
{
    value.generate(context);
}
void Instruction::I64Const::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x42);
    value.getValue(code);
}
void Instruction::F32Const::generate(Context *context)
{
    value.generate(context);
}
void Instruction::F32Const::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x43);
    value.getValue(code);
}
void Instruction::F64Const::generate(Context *context)
{
    value.generate(context);
}
void Instruction::F64Const::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x44);
    value.getValue(code);
}
void Instruction::I32Eqz::generate(Context *context)
{
}
void Instruction::I32Eqz::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x45);
}
void Instruction::I32Eq::generate(Context *context)
{
}
void Instruction::I32Eq::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x46);
}
void Instruction::I32Ne::generate(Context *context)
{
}
void Instruction::I32Ne::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x47);
}
void Instruction::I32LtS::generate(Context *context)
{
}
void Instruction::I32LtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x48);
}
void Instruction::I32LtU::generate(Context *context)
{
}
void Instruction::I32LtU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x49);
}
void Instruction::I32GtS::generate(Context *context)
{
}
void Instruction::I32GtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x4a);
}
void Instruction::I32GtU::generate(Context *context)
{
}
void Instruction::I32GtU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x4b);
}
void Instruction::I32LeS::generate(Context *context)
{
}
void Instruction::I32LeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x4c);
}
void Instruction::I32LeU::generate(Context *context)
{
}
void Instruction::I32LeU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x4d);
}
void Instruction::I32GeS::generate(Context *context)
{
}
void Instruction::I32GeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x4e);
}
void Instruction::I32GeU::generate(Context *context)
{
}
void Instruction::I32GeU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x4f);
}
void Instruction::I64Eqz::generate(Context *context)
{
}
void Instruction::I64Eqz::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x50);
}
void Instruction::I64Eq::generate(Context *context)
{
}
void Instruction::I64Eq::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x51);
}
void Instruction::I64Ne::generate(Context *context)
{
}
void Instruction::I64Ne::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x52);
}
void Instruction::I64LtS::generate(Context *context)
{
}
void Instruction::I64LtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x53);
}
void Instruction::I64LtU::generate(Context *context)
{
}
void Instruction::I64LtU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x54);
}
void Instruction::I64GtS::generate(Context *context)
{
}
void Instruction::I64GtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x55);
}
void Instruction::I64GtU::generate(Context *context)
{
}
void Instruction::I64GtU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x56);
}
void Instruction::I64LeS::generate(Context *context)
{
}
void Instruction::I64LeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x57);
}
void Instruction::I64LeU::generate(Context *context)
{
}
void Instruction::I64LeU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x58);
}
void Instruction::I64GeS::generate(Context *context)
{
}
void Instruction::I64GeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x59);
}
void Instruction::I64GeU::generate(Context *context)
{
}
void Instruction::I64GeU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x5a);
}
void Instruction::F32Eq::generate(Context *context)
{
}
void Instruction::F32Eq::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x5b);
}
void Instruction::F32Ne::generate(Context *context)
{
}
void Instruction::F32Ne::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x5c);
}
void Instruction::F32Lt::generate(Context *context)
{
}
void Instruction::F32Lt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x5d);
}
void Instruction::F32Gt::generate(Context *context)
{
}
void Instruction::F32Gt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x5e);
}
void Instruction::F32Le::generate(Context *context)
{
}
void Instruction::F32Le::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x5f);
}
void Instruction::F32Ge::generate(Context *context)
{
}
void Instruction::F32Ge::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x60);
}
void Instruction::F64Eq::generate(Context *context)
{
}
void Instruction::F64Eq::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x61);
}
void Instruction::F64Ne::generate(Context *context)
{
}
void Instruction::F64Ne::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x62);
}
void Instruction::F64Lt::generate(Context *context)
{
}
void Instruction::F64Lt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x63);
}
void Instruction::F64Gt::generate(Context *context)
{
}
void Instruction::F64Gt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x64);
}
void Instruction::F64Le::generate(Context *context)
{
}
void Instruction::F64Le::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x65);
}
void Instruction::F64Ge::generate(Context *context)
{
}
void Instruction::F64Ge::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x66);
}
void Instruction::I32Clz::generate(Context *context)
{
}
void Instruction::I32Clz::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x67);
}
void Instruction::I32Ctz::generate(Context *context)
{
}
void Instruction::I32Ctz::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x68);
}
void Instruction::I32Popcnt::generate(Context *context)
{
}
void Instruction::I32Popcnt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x69);
}
void Instruction::I32Add::generate(Context *context)
{
}
void Instruction::I32Add::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x6a);
}
void Instruction::I32Sub::generate(Context *context)
{
}
void Instruction::I32Sub::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x6b);
}
void Instruction::I32Mul::generate(Context *context)
{
}
void Instruction::I32Mul::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x6c);
}
void Instruction::I32DivS::generate(Context *context)
{
}
void Instruction::I32DivS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x6d);
}
void Instruction::I32DivU::generate(Context *context)
{
}
void Instruction::I32DivU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x6e);
}
void Instruction::I32RemS::generate(Context *context)
{
}
void Instruction::I32RemS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x6f);
}
void Instruction::I32RemU::generate(Context *context)
{
}
void Instruction::I32RemU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x70);
}
void Instruction::I32And::generate(Context *context)
{
}
void Instruction::I32And::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x71);
}
void Instruction::I32Or::generate(Context *context)
{
}
void Instruction::I32Or::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x72);
}
void Instruction::I32Xor::generate(Context *context)
{
}
void Instruction::I32Xor::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x73);
}
void Instruction::I32Shl::generate(Context *context)
{
}
void Instruction::I32Shl::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x74);
}
void Instruction::I32ShrS::generate(Context *context)
{
}
void Instruction::I32ShrS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x75);
}
void Instruction::I32ShrU::generate(Context *context)
{
}
void Instruction::I32ShrU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x76);
}
void Instruction::I32Rotl::generate(Context *context)
{
}
void Instruction::I32Rotl::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x77);
}
void Instruction::I32Rotr::generate(Context *context)
{
}
void Instruction::I32Rotr::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x78);
}
void Instruction::I64Clz::generate(Context *context)
{
}
void Instruction::I64Clz::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x79);
}
void Instruction::I64Ctz::generate(Context *context)
{
}
void Instruction::I64Ctz::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x7a);
}
void Instruction::I64Popcnt::generate(Context *context)
{
}
void Instruction::I64Popcnt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x7b);
}
void Instruction::I64Add::generate(Context *context)
{
}
void Instruction::I64Add::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x7c);
}

void Instruction::I64Sub::generate(Context *context)
{
}
void Instruction::I64Sub::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x7d);
}
void Instruction::I64Mul::generate(Context *context)
{
}
void Instruction::I64Mul::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x7e);
}
void Instruction::I64DivS::generate(Context *context)
{
}
void Instruction::I64DivS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x7f);
}
void Instruction::I64DivU::generate(Context *context)
{
}
void Instruction::I64DivU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x80);
}
void Instruction::I64RemS::generate(Context *context)
{
}
void Instruction::I64RemS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x81);
}
void Instruction::I64RemU::generate(Context *context)
{
}
void Instruction::I64RemU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x82);
}
void Instruction::I64And::generate(Context *context)
{
}
void Instruction::I64And::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x83);
}
void Instruction::I64Or::generate(Context *context)
{
}
void Instruction::I64Or::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x84);
}
void Instruction::I64Xor::generate(Context *context)
{
}
void Instruction::I64Xor::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x85);
}
void Instruction::I64Shl::generate(Context *context)
{
}
void Instruction::I64Shl::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x86);
}
void Instruction::I64ShrS::generate(Context *context)
{
}
void Instruction::I64ShrS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x87);
}
void Instruction::I64ShrU::generate(Context *context)
{
}
void Instruction::I64ShrU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x88);
}
void Instruction::I64Rotl::generate(Context *context)
{
}
void Instruction::I64Rotl::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x89);
}
void Instruction::I64Rotr::generate(Context *context)
{
}
void Instruction::I64Rotr::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x8A);
}
void Instruction::F32Abs::generate(Context *context)
{
}
void Instruction::F32Abs::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x8B);
}
void Instruction::F32Neg::generate(Context *context)
{
}
void Instruction::F32Neg::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x8c);
}
void Instruction::F32Ceil::generate(Context *context)
{
}
void Instruction::F32Ceil::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x8d);
}
void Instruction::F32Floor::generate(Context *context)
{
}
void Instruction::F32Floor::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x8e);
}
void Instruction::F32Trunc::generate(Context *context)
{
}
void Instruction::F32Trunc::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x8f);
}
void Instruction::F32Nearest::generate(Context *context)
{
}
void Instruction::F32Nearest::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x90);
}
void Instruction::F32Sqrt::generate(Context *context)
{
}
void Instruction::F32Sqrt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x91);
}
void Instruction::F32Add::generate(Context *context)
{
}
void Instruction::F32Add::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x92);
}
void Instruction::F32Sub::generate(Context *context)
{
}
void Instruction::F32Sub::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x93);
}
void Instruction::F32Mul::generate(Context *context)
{
}
void Instruction::F32Mul::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x94);
}
void Instruction::F32Div::generate(Context *context)
{
}
void Instruction::F32Div::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x95);
}
void Instruction::F32Min::generate(Context *context)
{
}
void Instruction::F32Min::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x96);
}
void Instruction::F32Max::generate(Context *context)
{
}
void Instruction::F32Max::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x97);
}
void Instruction::F32Copysign::generate(Context *context)
{
}
void Instruction::F32Copysign::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x98);
}
void Instruction::F64Abs::generate(Context *context)
{
}
void Instruction::F64Abs::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x99);
}
void Instruction::F64Neg::generate(Context *context)
{
}
void Instruction::F64Neg::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x9a);
}
void Instruction::F64Ceil::generate(Context *context)
{
}
void Instruction::F64Ceil::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x9b);
}
void Instruction::F64Floor::generate(Context *context)
{
}
void Instruction::F64Floor::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x9c);
}
void Instruction::F64Trunc::generate(Context *context)
{
}
void Instruction::F64Trunc::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x9d);
}
void Instruction::F64Nearest::generate(Context *context)
{
}
void Instruction::F64Nearest::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x9e);
}
void Instruction::F64Sqrt::generate(Context *context)
{
}
void Instruction::F64Sqrt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x9f);
}
void Instruction::F64Add::generate(Context *context)
{
}
void Instruction::F64Add::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xa0);
}
void Instruction::F64Sub::generate(Context *context)
{
}
void Instruction::F64Sub::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xa1);
}
void Instruction::F64Mul::generate(Context *context)
{
}
void Instruction::F64Mul::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xa2);
}
void Instruction::F64Div::generate(Context *context)
{
}
void Instruction::F64Div::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xa3);
}
void Instruction::F64Min::generate(Context *context)
{
}
void Instruction::F64Min::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xa4);
}
void Instruction::F64Max::generate(Context *context)
{
}
void Instruction::F64Max::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xa5);
}
void Instruction::F64Copysign::generate(Context *context)
{
}
void Instruction::F64Copysign::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xa6);
}
void Instruction::I32WrapI64::generate(Context *context)
{
}
void Instruction::I32WrapI64::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xa7);
}
void Instruction::I32TruncF32S::generate(Context *context)
{
}
void Instruction::I32TruncF32S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xa8);
}
void Instruction::I32TruncF32U::generate(Context *context)
{
}
void Instruction::I32TruncF32U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xa9);
}
void Instruction::I32TruncF64S::generate(Context *context)
{
}
void Instruction::I32TruncF64S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xaa);
}
void Instruction::I32TruncF64U::generate(Context *context)
{
}
void Instruction::I32TruncF64U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xab);
}
void Instruction::I64ExtendI32S::generate(Context *context)
{
}
void Instruction::I64ExtendI32S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xac);
}
void Instruction::I64ExtendI32U::generate(Context *context)
{
}
void Instruction::I64ExtendI32U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xad);
}
void Instruction::I64TruncF32S::generate(Context *context)
{
}
void Instruction::I64TruncF32S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xae);
}
void Instruction::I64TruncF32U::generate(Context *context)
{
}
void Instruction::I64TruncF32U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xaf);
}
void Instruction::I64TruncF64S::generate(Context *context)
{
}
void Instruction::I64TruncF64S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xb0);
}
void Instruction::I64TruncF64U::generate(Context *context)
{
}
void Instruction::I64TruncF64U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xb1);
}
void Instruction::F32ConvertI32S::generate(Context *context)
{
}
void Instruction::F32ConvertI32S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xb2);
}
void Instruction::F32ConvertI32U::generate(Context *context)
{
}
void Instruction::F32ConvertI32U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xb3);
}
void Instruction::F32ConvertI64S::generate(Context *context)
{
}
void Instruction::F32ConvertI64S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xb4);
}
void Instruction::F32ConvertI64U::generate(Context *context)
{
}
void Instruction::F32ConvertI64U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xb5);
}
void Instruction::F32DemoteF64::generate(Context *context)
{
}
void Instruction::F32DemoteF64::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xb6);
}
void Instruction::F64ConvertI32S::generate(Context *context)
{
}
void Instruction::F64ConvertI32S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xb7);
}
void Instruction::F64ConvertI32U::generate(Context *context)
{
}
void Instruction::F64ConvertI32U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xb8);
}
void Instruction::F64ConvertI64S::generate(Context *context)
{
}
void Instruction::F64ConvertI64S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xb9);
}
void Instruction::F64ConvertI64U::generate(Context *context)
{
}
void Instruction::F64ConvertI64U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xba);
}
void Instruction::F64PromoteF32::generate(Context *context)
{
}
void Instruction::F64PromoteF32::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xbb);
}
void Instruction::I32ReinterpretF32::generate(Context *context)
{
}
void Instruction::I32ReinterpretF32::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xbc);
}
void Instruction::I64ReinterpretF64::generate(Context *context)
{
}
void Instruction::I64ReinterpretF64::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xbd);
}
void Instruction::F32ReinterpretI32::generate(Context *context)
{
}
void Instruction::F32ReinterpretI32::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xbe);
}
void Instruction::F64ReinterpretI64::generate(Context *context)
{
}
void Instruction::F64ReinterpretI64::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xbf);
}
void Instruction::I32Extend8S::generate(Context *context)
{
}
void Instruction::I32Extend8S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xc0);
}
void Instruction::I32Extend16S::generate(Context *context)
{
}
void Instruction::I32Extend16S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xc1);
}
void Instruction::I64Extend8S::generate(Context *context)
{
}
void Instruction::I64Extend8S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xc2);
}
void Instruction::I64Extend16S::generate(Context *context)
{
}
void Instruction::I64Extend16S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xc3);
}
void Instruction::I64Extend32S::generate(Context *context)
{
}
void Instruction::I64Extend32S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xc4);
}
void Instruction::I32TruncSatF32S::generate(Context *context)
{
}
void Instruction::I32TruncSatF32S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(0, code);
}
void Instruction::I32TruncSatF32U::generate(Context *context)
{
}
void Instruction::I32TruncSatF32U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(1, code);
}
void Instruction::I32TruncSatF64S::generate(Context *context)
{
}
void Instruction::I32TruncSatF64S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(2, code);
}
void Instruction::I32TruncSatF64U::generate(Context *context)
{
}
void Instruction::I32TruncSatF64U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(3, code);
}
void Instruction::I64TruncSatF32S::generate(Context *context)
{
}
void Instruction::I64TruncSatF32S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(4, code);
}
void Instruction::I64TruncSatF32U::generate(Context *context)
{
}
void Instruction::I64TruncSatF32U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(5, code);
}
void Instruction::I64TruncSatF64S::generate(Context *context)
{
}
void Instruction::I64TruncSatF64S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(6, code);
}
void Instruction::I64TruncSatF64U::generate(Context *context)
{
}
void Instruction::I64TruncSatF64U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(7, code);
}
// Reference types instructions.
void Instruction::TypedSelect::generate(Context *context)
{
    ty = CHOICE(Sections::valTypes);
}
void Instruction::TypedSelect::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x1c);
    unsigned_to_leb128(1, code);
    code->write_byte(ty);
}
void Instruction::RefNull::generate(Context *context)
{
    if (context->random->gbool())
        ty = Sections::FuncRef;
    else
        ty = Sections::ExternRef;
}
void Instruction::RefNull::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xd0);
    code->write_byte(ty);
}
void Instruction::RefIsNull::generate(Context *context)
{
}
void Instruction::RefIsNull::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xd1);
}
void Instruction::RefFunc::generate(Context *context)
{
    f.generate(context);
}
void Instruction::RefFunc::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xd2);
    f.getValue(code);
}

// Bulk memory instructions.
void Instruction::TableInit::generate(Context *context)
{
    segment.generate(context);
    table.generate(context);
}
void Instruction::TableInit::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(0x0c, code);
    segment.getValue(code);
    table.getValue(code);
}
void Instruction::ElemDrop::generate(Context *context)
{
    segment.generate(context);
}
void Instruction::ElemDrop::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(0x0d, code);
    segment.getValue(code);
}
void Instruction::TableFill::generate(Context *context)
{
    table.generate(context);
}
void Instruction::TableFill::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(0x11, code);
    table.getValue(code);
}
void Instruction::TableSet::generate(Context *context)
{
    table.generate(context);
}
void Instruction::TableSet::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x26);
    table.getValue(code);
}
void Instruction::TableGet::generate(Context *context)
{
    table.generate(context);
}
void Instruction::TableGet::getByteCode(DataOutputStream *code)
{
    code->write_byte(0x25);
    table.getValue(code);
}
void Instruction::TableGrow::generate(Context *context)
{
    table.generate(context);
}
void Instruction::TableGrow::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(0x0f, code);
    table.getValue(code);
}
void Instruction::TableSize::generate(Context *context)
{
    table.generate(context);
}
void Instruction::TableSize::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(0x10, code);
    table.getValue(code);
}
void Instruction::TableCopy::generate(Context *context)
{
    dst.generate(context);
    src.generate(context);
}
void Instruction::TableCopy::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfc);
    unsigned_to_leb128(0x0e, code);
    dst.getValue(code);
    src.getValue(code);
}
// SIMD instructions.
void Instruction::V128Load::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x00, code);
    memarg.getValue(code);
}
void Instruction::V128Load8x8S::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load8x8S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x01, code);
    memarg.getValue(code);
}
void Instruction::V128Load8x8U::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load8x8U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x02, code);
    memarg.getValue(code);
}
void Instruction::V128Load16x4S::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load16x4S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x03, code);
    memarg.getValue(code);
}
void Instruction::V128Load16x4U::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load16x4U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x04, code);
    memarg.getValue(code);
}
void Instruction::V128Load32x2S::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load32x2S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x05, code);
    memarg.getValue(code);
}
void Instruction::V128Load32x2U::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load32x2U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x06, code);
    memarg.getValue(code);
}
void Instruction::V128Load8Splat::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load8Splat::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x07, code);
    memarg.getValue(code);
}
void Instruction::V128Load16Splat::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load16Splat::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x08, code);
    memarg.getValue(code);
}
void Instruction::V128Load32Splat::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load32Splat::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x09, code);
    memarg.getValue(code);
}
void Instruction::V128Load64Splat::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load64Splat::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x0a, code);
    memarg.getValue(code);
}
void Instruction::V128Load32Zero::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load32Zero::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x5c, code);
    memarg.getValue(code);
}
void Instruction::V128Load64Zero::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Load64Zero::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x5d, code);
    memarg.getValue(code);
}
void Instruction::V128Store::generate(Context *context)
{
    memarg.generate(context);
}
void Instruction::V128Store::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x0b, code);
    memarg.getValue(code);
}
void Instruction::V128Load8Lane::generate(Context *context)
{
    memarg.generate(context);
    lane.generate(context);
}
void Instruction::V128Load8Lane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x54, code);
    memarg.getValue(code);
    lane.getValue(code);
}
void Instruction::V128Load16Lane::generate(Context *context)
{
    memarg.generate(context);
    lane.generate(context);
}
void Instruction::V128Load16Lane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x55, code);
    memarg.getValue(code);
    lane.getValue(code);
}
void Instruction::V128Load32Lane::generate(Context *context)
{
    memarg.generate(context);
    lane.generate(context);
}
void Instruction::V128Load32Lane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x56, code);
    memarg.getValue(code);
    lane.getValue(code);
}
void Instruction::V128Load64Lane::generate(Context *context)
{
    memarg.generate(context);
    lane.generate(context);
}
void Instruction::V128Load64Lane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x57, code);
    memarg.getValue(code);
    lane.getValue(code);
}
void Instruction::V128Store8Lane::generate(Context *context)
{
    memarg.generate(context);
    lane.generate(context);
}
void Instruction::V128Store8Lane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x58, code);
    memarg.getValue(code);
    lane.getValue(code);
}
void Instruction::V128Store16Lane::generate(Context *context)
{
    memarg.generate(context);
    lane.generate(context);
}
void Instruction::V128Store16Lane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x59, code);
    memarg.getValue(code);
    lane.getValue(code);
}
void Instruction::V128Store32Lane::generate(Context *context)
{
    memarg.generate(context);
    lane.generate(context);
}
void Instruction::V128Store32Lane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x5a, code);
    memarg.getValue(code);
    lane.getValue(code);
}
void Instruction::V128Store64Lane::generate(Context *context)
{
    memarg.generate(context);
    lane.generate(context);
}
void Instruction::V128Store64Lane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x5b, code);
    memarg.getValue(code);
    lane.getValue(code);
}
void Instruction::V128Const::generate(Context *context)
{
    x.generate(context);
}
void Instruction::V128Const::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x0c, code);
    x.getValue(code);
}
void Instruction::I8x16Shuffle::generate(Context *context)
{
    for (int i = 0; i < 16; i++)
    {
        lanes[i].generate(context);
    }
}
void Instruction::I8x16Shuffle::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x0d, code);
    for (int i = 0; i < 16; i++)
    {
        lanes[i].getValue(code);
    }
}
void Instruction::I8x16ExtractLaneS::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::I8x16ExtractLaneS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x15, code);
    lane.getValue(code);
}
void Instruction::I8x16ExtractLaneU::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::I8x16ExtractLaneU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x16, code);
    lane.getValue(code);
}
void Instruction::I8x16ReplaceLane::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::I8x16ReplaceLane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x17, code);
    lane.getValue(code);
}
void Instruction::I16x8ExtractLaneS::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::I16x8ExtractLaneS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x18, code);
    lane.getValue(code);
}
void Instruction::I16x8ExtractLaneU::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::I16x8ExtractLaneU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x19, code);
    lane.getValue(code);
}
void Instruction::I16x8ReplaceLane::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::I16x8ReplaceLane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x1a, code);
    lane.getValue(code);
}
void Instruction::I32x4ExtractLane::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::I32x4ExtractLane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x1b, code);
    lane.getValue(code);
}
void Instruction::I32x4ReplaceLane::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::I32x4ReplaceLane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x1c, code);
    lane.getValue(code);
}
void Instruction::I64x2ExtractLane::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::I64x2ExtractLane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x1d, code);
    lane.getValue(code);
}
void Instruction::I64x2ReplaceLane::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::I64x2ReplaceLane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x1e, code);
    lane.getValue(code);
}
void Instruction::F32x4ExtractLane::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::F32x4ExtractLane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x1f, code);
    lane.getValue(code);
}
void Instruction::F32x4ReplaceLane::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::F32x4ReplaceLane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x20, code);
    lane.getValue(code);
}
void Instruction::F64x2ExtractLane::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::F64x2ExtractLane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x21, code);
    lane.getValue(code);
}
void Instruction::F64x2ReplaceLane::generate(Context *context)
{
    lane.generate(context);
}
void Instruction::F64x2ReplaceLane::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x22, code);
    lane.getValue(code);
}
void Instruction::I8x16Swizzle::generate(Context *context)
{
}
void Instruction::I8x16Swizzle::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x0e, code);
}
void Instruction::I8x16Splat::generate(Context *context)
{
}
void Instruction::I8x16Splat::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x0f, code);
}
void Instruction::I16x8Splat::generate(Context *context)
{
}
void Instruction::I16x8Splat::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x10, code);
}
void Instruction::I32x4Splat::generate(Context *context)
{
}
void Instruction::I32x4Splat::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x11, code);
}
void Instruction::I64x2Splat::generate(Context *context)
{
}
void Instruction::I64x2Splat::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x12, code);
}
void Instruction::F32x4Splat::generate(Context *context)
{
}
void Instruction::F32x4Splat::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x13, code);
}
void Instruction::F64x2Splat::generate(Context *context)
{
}
void Instruction::F64x2Splat::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x14, code);
}
void Instruction::I8x16Eq::generate(Context *context)
{
}
void Instruction::I8x16Eq::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x23, code);
}
void Instruction::I8x16Ne::generate(Context *context)
{
}
void Instruction::I8x16Ne::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x24, code);
}
void Instruction::I8x16LtS::generate(Context *context)
{
}
void Instruction::I8x16LtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x25, code);
}
void Instruction::I8x16LtU::generate(Context *context)
{
}
void Instruction::I8x16LtU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x26, code);
}
void Instruction::I8x16GtS::generate(Context *context)
{
}
void Instruction::I8x16GtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x27, code);
}
void Instruction::I8x16GtU::generate(Context *context)
{
}
void Instruction::I8x16GtU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x28, code);
}
void Instruction::I8x16LeS::generate(Context *context)
{
}
void Instruction::I8x16LeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x29, code);
}
void Instruction::I8x16LeU::generate(Context *context)
{
}
void Instruction::I8x16LeU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x2a, code);
}
void Instruction::I8x16GeS::generate(Context *context)
{
}
void Instruction::I8x16GeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x2b, code);
}
void Instruction::I8x16GeU::generate(Context *context)
{
}
void Instruction::I8x16GeU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x2c, code);
}
void Instruction::I16x8Eq::generate(Context *context)
{
}
void Instruction::I16x8Eq::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x2d, code);
}
void Instruction::I16x8Ne::generate(Context *context)
{
}
void Instruction::I16x8Ne::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x2e, code);
}
void Instruction::I16x8LtS::generate(Context *context)
{
}
void Instruction::I16x8LtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x2f, code);
}
void Instruction::I16x8LtU::generate(Context *context)
{
}
void Instruction::I16x8LtU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x30, code);
}
void Instruction::I16x8GtS::generate(Context *context)
{
}
void Instruction::I16x8GtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x31, code);
}
void Instruction::I16x8GtU::generate(Context *context)
{
}
void Instruction::I16x8GtU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x32, code);
}
void Instruction::I16x8LeS::generate(Context *context)
{
}
void Instruction::I16x8LeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x33, code);
}

void Instruction::I16x8LeU::generate(Context *context)
{
}
void Instruction::I16x8LeU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x34, code);
}
void Instruction::I16x8GeS::generate(Context *context)
{
}
void Instruction::I16x8GeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x35, code);
}
void Instruction::I16x8GeU::generate(Context *context)
{
}
void Instruction::I16x8GeU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x36, code);
}
void Instruction::I32x4Eq::generate(Context *context)
{
}
void Instruction::I32x4Eq::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x37, code);
}
void Instruction::I32x4Ne::generate(Context *context)
{
}
void Instruction::I32x4Ne::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x38, code);
}
void Instruction::I32x4LtS::generate(Context *context)
{
}
void Instruction::I32x4LtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x39, code);
}
void Instruction::I32x4LtU::generate(Context *context)
{
}
void Instruction::I32x4LtU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x3a, code);
}
void Instruction::I32x4GtS::generate(Context *context)
{
}
void Instruction::I32x4GtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x3b, code);
}
void Instruction::I32x4GtU::generate(Context *context)
{
}
void Instruction::I32x4GtU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x3c, code);
}
void Instruction::I32x4LeS::generate(Context *context)
{
}
void Instruction::I32x4LeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x3d, code);
}
void Instruction::I32x4LeU::generate(Context *context)
{
}
void Instruction::I32x4LeU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x3e, code);
}
void Instruction::I32x4GeS::generate(Context *context)
{
}
void Instruction::I32x4GeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x3f, code);
}
void Instruction::I32x4GeU::generate(Context *context)
{
}
void Instruction::I32x4GeU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x40, code);
}
void Instruction::I64x2Eq::generate(Context *context)
{
}
void Instruction::I64x2Eq::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xd6, code);
}
void Instruction::I64x2Ne::generate(Context *context)
{
}
void Instruction::I64x2Ne::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xd7, code);
}
void Instruction::I64x2LtS::generate(Context *context)
{
}
void Instruction::I64x2LtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xd8, code);
}
void Instruction::I64x2GtS::generate(Context *context)
{
}
void Instruction::I64x2GtS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xd9, code);
}
void Instruction::I64x2LeS::generate(Context *context)
{
}
void Instruction::I64x2LeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xdd, code);
}
void Instruction::I64x2GeS::generate(Context *context)
{
}
void Instruction::I64x2GeS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xdb, code);
}
void Instruction::F32x4Eq::generate(Context *context)
{
}
void Instruction::F32x4Eq::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x41, code);
}
void Instruction::F32x4Ne::generate(Context *context)
{
}
void Instruction::F32x4Ne::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x42, code);
}
void Instruction::F32x4Lt::generate(Context *context)
{
}
void Instruction::F32x4Lt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x43, code);
}
void Instruction::F32x4Gt::generate(Context *context)
{
}
void Instruction::F32x4Gt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x44, code);
}
void Instruction::F32x4Le::generate(Context *context)
{
}
void Instruction::F32x4Le::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x45, code);
}
void Instruction::F32x4Ge::generate(Context *context)
{
}
void Instruction::F32x4Ge::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x46, code);
}
void Instruction::F64x2Eq::generate(Context *context)
{
}
void Instruction::F64x2Eq::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x47, code);
}
void Instruction::F64x2Ne::generate(Context *context)
{
}
void Instruction::F64x2Ne::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x48, code);
}
void Instruction::F64x2Lt::generate(Context *context)
{
}
void Instruction::F64x2Lt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x49, code);
}
void Instruction::F64x2Gt::generate(Context *context)
{
}
void Instruction::F64x2Gt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x4a, code);
}
void Instruction::F64x2Le::generate(Context *context)
{
}
void Instruction::F64x2Le::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x4b, code);
}
void Instruction::F64x2Ge::generate(Context *context)
{
}
void Instruction::F64x2Ge::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x4c, code);
}
void Instruction::V128Not::generate(Context *context)
{
}
void Instruction::V128Not::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x4d, code);
}
void Instruction::V128And::generate(Context *context)
{
}
void Instruction::V128And::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x4e, code);
}
void Instruction::V128AndNot::generate(Context *context)
{
}
void Instruction::V128AndNot::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x4f, code);
}
void Instruction::V128Or::generate(Context *context)
{
}
void Instruction::V128Or::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x50, code);
}
void Instruction::V128Xor::generate(Context *context)
{
}
void Instruction::V128Xor::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x51, code);
}
void Instruction::V128Bitselect::generate(Context *context)
{
}
void Instruction::V128Bitselect::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x52, code);
}
void Instruction::V128AnyTrue::generate(Context *context)
{
}
void Instruction::V128AnyTrue::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x53, code);
}
void Instruction::I8x16Abs::generate(Context *context)
{
}
void Instruction::I8x16Abs::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x60, code);
}
void Instruction::I8x16Neg::generate(Context *context)
{
}
void Instruction::I8x16Neg::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x61, code);
}
void Instruction::I8x16Popcnt::generate(Context *context)
{
}

void Instruction::I8x16Popcnt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x62, code);
}
void Instruction::I8x16AllTrue::generate(Context *context)
{
}
void Instruction::I8x16AllTrue::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x63, code);
}
void Instruction::I8x16Bitmask::generate(Context *context)
{
}
void Instruction::I8x16Bitmask::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x64, code);
}
void Instruction::I8x16NarrowI16x8S::generate(Context *context)
{
}
void Instruction::I8x16NarrowI16x8S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x65, code);
}
void Instruction::I8x16NarrowI16x8U::generate(Context *context)
{
}
void Instruction::I8x16NarrowI16x8U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x66, code);
}
void Instruction::I8x16Shl::generate(Context *context)
{
}
void Instruction::I8x16Shl::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x6b, code);
}
void Instruction::I8x16ShrS::generate(Context *context)
{
}
void Instruction::I8x16ShrS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x6c, code);
}
void Instruction::I8x16ShrU::generate(Context *context)
{
}
void Instruction::I8x16ShrU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x6d, code);
}
void Instruction::I8x16Add::generate(Context *context)
{
}
void Instruction::I8x16Add::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x6e, code);
}
void Instruction::I8x16AddSatS::generate(Context *context)
{
}
void Instruction::I8x16AddSatS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x6f, code);
}
void Instruction::I8x16AddSatU::generate(Context *context)
{
}
void Instruction::I8x16AddSatU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x70, code);
}
void Instruction::I8x16Sub::generate(Context *context)
{
}
void Instruction::I8x16Sub::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x71, code);
}
void Instruction::I8x16SubSatS::generate(Context *context)
{
}
void Instruction::I8x16SubSatS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x72, code);
}
void Instruction::I8x16SubSatU::generate(Context *context)
{
}
void Instruction::I8x16SubSatU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x73, code);
}
void Instruction::I8x16MinS::generate(Context *context)
{
}
void Instruction::I8x16MinS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x76, code);
}
void Instruction::I8x16MinU::generate(Context *context)
{
}
void Instruction::I8x16MinU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x77, code);
}
void Instruction::I8x16MaxS::generate(Context *context)
{
}
void Instruction::I8x16MaxS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x78, code);
}
void Instruction::I8x16MaxU::generate(Context *context)
{
}
void Instruction::I8x16MaxU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x79, code);
}
void Instruction::I8x16RoundingAverageU::generate(Context *context)
{
}
void Instruction::I8x16RoundingAverageU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x7b, code);
}
void Instruction::I16x8ExtAddPairwiseI8x16S::generate(Context *context)
{
}
void Instruction::I16x8ExtAddPairwiseI8x16S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x7c, code);
}
void Instruction::I16x8ExtAddPairwiseI8x16U::generate(Context *context)
{
}
void Instruction::I16x8ExtAddPairwiseI8x16U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x7d, code);
}
void Instruction::I16x8Abs::generate(Context *context)
{
}
void Instruction::I16x8Abs::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x7e, code);
}
void Instruction::I16x8Neg::generate(Context *context)
{
}
void Instruction::I16x8Neg::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x7f, code);
}
void Instruction::I16x8Q15MulrSatS::generate(Context *context)
{
}
void Instruction::I16x8Q15MulrSatS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x82, code);
}
void Instruction::I16x8AllTrue::generate(Context *context)
{
}
void Instruction::I16x8AllTrue::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x83, code);
}
void Instruction::I16x8Bitmask::generate(Context *context)
{
}
void Instruction::I16x8Bitmask::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x84, code);
}
void Instruction::I16x8NarrowI32x4S::generate(Context *context)
{
}
void Instruction::I16x8NarrowI32x4S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x85, code);
}
void Instruction::I16x8NarrowI32x4U::generate(Context *context)
{
}
void Instruction::I16x8NarrowI32x4U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x86, code);
}
void Instruction::I16x8ExtendLowI8x16S::generate(Context *context)
{
}
void Instruction::I16x8ExtendLowI8x16S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x87, code);
}
void Instruction::I16x8ExtendHighI8x16S::generate(Context *context)
{
}
void Instruction::I16x8ExtendHighI8x16S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x88, code);
}
void Instruction::I16x8ExtendLowI8x16U::generate(Context *context)
{
}
void Instruction::I16x8ExtendLowI8x16U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x89, code);
}
void Instruction::I16x8ExtendHighI8x16U::generate(Context *context)
{
}
void Instruction::I16x8ExtendHighI8x16U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x8a, code);
}
void Instruction::I16x8Shl::generate(Context *context)
{
}
void Instruction::I16x8Shl::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x8b, code);
}
void Instruction::I16x8ShrS::generate(Context *context)
{
}
void Instruction::I16x8ShrS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x8c, code);
}
void Instruction::I16x8ShrU::generate(Context *context)
{
}
void Instruction::I16x8ShrU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x8d, code);
}
void Instruction::I16x8Add::generate(Context *context)
{
}
void Instruction::I16x8Add::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x8e, code);
}
void Instruction::I16x8AddSatS::generate(Context *context)
{
}
void Instruction::I16x8AddSatS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x8f, code);
}
void Instruction::I16x8AddSatU::generate(Context *context)
{
}
void Instruction::I16x8AddSatU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x90, code);
}
void Instruction::I16x8Sub::generate(Context *context)
{
}
void Instruction::I16x8Sub::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x91, code);
}
void Instruction::I16x8SubSatS::generate(Context *context)
{
}
void Instruction::I16x8SubSatS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x92, code);
}
void Instruction::I16x8SubSatU::generate(Context *context)
{
}
void Instruction::I16x8SubSatU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x93, code);
}
void Instruction::I16x8Mul::generate(Context *context)
{
}
void Instruction::I16x8Mul::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x95, code);
}
void Instruction::I16x8MinS::generate(Context *context)
{
}
void Instruction::I16x8MinS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x96, code);
}
void Instruction::I16x8MinU::generate(Context *context)
{
}
void Instruction::I16x8MinU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x97, code);
}
void Instruction::I16x8MaxS::generate(Context *context)
{
}
void Instruction::I16x8MaxS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x98, code);
}
void Instruction::I16x8MaxU::generate(Context *context)
{
}
void Instruction::I16x8MaxU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x99, code);
}
void Instruction::I16x8RoundingAverageU::generate(Context *context)
{
}
void Instruction::I16x8RoundingAverageU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x9b, code);
}
void Instruction::I16x8ExtMulLowI8x16S::generate(Context *context)
{
}
void Instruction::I16x8ExtMulLowI8x16S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x9c, code);
}
void Instruction::I16x8ExtMulHighI8x16S::generate(Context *context)
{
}
void Instruction::I16x8ExtMulHighI8x16S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x9d, code);
}
void Instruction::I16x8ExtMulLowI8x16U::generate(Context *context)
{
}
void Instruction::I16x8ExtMulLowI8x16U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x9e, code);
}
void Instruction::I16x8ExtMulHighI8x16U::generate(Context *context)
{
}
void Instruction::I16x8ExtMulHighI8x16U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x9f, code);
}
void Instruction::I32x4ExtAddPairwiseI16x8S::generate(Context *context)
{
}
void Instruction::I32x4ExtAddPairwiseI16x8S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x7e, code);
}
void Instruction::I32x4ExtAddPairwiseI16x8U::generate(Context *context)
{
}
void Instruction::I32x4ExtAddPairwiseI16x8U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x7f, code);
}
void Instruction::I32x4Abs::generate(Context *context)
{
}
void Instruction::I32x4Abs::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xa0, code);
}
void Instruction::I32x4Neg::generate(Context *context)
{
}
void Instruction::I32x4Neg::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xa1, code);
}
void Instruction::I32x4AllTrue::generate(Context *context)
{
}
void Instruction::I32x4AllTrue::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xa3, code);
}
void Instruction::I32x4Bitmask::generate(Context *context)
{
}
void Instruction::I32x4Bitmask::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xa4, code);
}
void Instruction::I32x4ExtendLowI16x8S::generate(Context *context)
{
}
void Instruction::I32x4ExtendLowI16x8S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xa7, code);
}
void Instruction::I32x4ExtendHighI16x8S::generate(Context *context)
{
}
void Instruction::I32x4ExtendHighI16x8S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xa8, code);
}
void Instruction::I32x4ExtendLowI16x8U::generate(Context *context)
{
}
void Instruction::I32x4ExtendLowI16x8U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xa9, code);
}
void Instruction::I32x4ExtendHighI16x8U::generate(Context *context)
{
}
void Instruction::I32x4ExtendHighI16x8U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xaa, code);
}
void Instruction::I32x4Shl::generate(Context *context)
{
}
void Instruction::I32x4Shl::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xab, code);
}
void Instruction::I32x4ShrS::generate(Context *context)
{
}
void Instruction::I32x4ShrS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xac, code);
}
void Instruction::I32x4ShrU::generate(Context *context)
{
}
void Instruction::I32x4ShrU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xad, code);
}
void Instruction::I32x4Add::generate(Context *context)
{
}
void Instruction::I32x4Add::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xae, code);
}
void Instruction::I32x4Sub::generate(Context *context)
{
}
void Instruction::I32x4Sub::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xb1, code);
}
void Instruction::I32x4Mul::generate(Context *context)
{
}
void Instruction::I32x4Mul::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xb5, code);
}
void Instruction::I32x4MinS::generate(Context *context)
{
}
void Instruction::I32x4MinS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xb6, code);
}
void Instruction::I32x4MinU::generate(Context *context)
{
}
void Instruction::I32x4MinU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xb7, code);
}
void Instruction::I32x4MaxS::generate(Context *context)
{
}
void Instruction::I32x4MaxS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xb8, code);
}
void Instruction::I32x4MaxU::generate(Context *context)
{
}
void Instruction::I32x4MaxU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xb9, code);
}
void Instruction::I32x4DotI16x8S::generate(Context *context)
{
}
void Instruction::I32x4DotI16x8S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xba, code);
}
void Instruction::I32x4ExtMulLowI16x8S::generate(Context *context)
{
}
void Instruction::I32x4ExtMulLowI16x8S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xbc, code);
}
void Instruction::I32x4ExtMulHighI16x8S::generate(Context *context)
{
}
void Instruction::I32x4ExtMulHighI16x8S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xbd, code);
}
void Instruction::I32x4ExtMulLowI16x8U::generate(Context *context)
{
}
void Instruction::I32x4ExtMulLowI16x8U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xbe, code);
}
void Instruction::I32x4ExtMulHighI16x8U::generate(Context *context)
{
}
void Instruction::I32x4ExtMulHighI16x8U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xbf, code);
}
void Instruction::I64x2Abs::generate(Context *context)
{
}
void Instruction::I64x2Abs::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xc0, code);
}
void Instruction::I64x2Neg::generate(Context *context)
{
}
void Instruction::I64x2Neg::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xc1, code);
}
void Instruction::I64x2AllTrue::generate(Context *context)
{
}
void Instruction::I64x2AllTrue::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xc3, code);
}
void Instruction::I64x2Bitmask::generate(Context *context)
{
}
void Instruction::I64x2Bitmask::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xc4, code);
}
void Instruction::I64x2ExtendLowI32x4S::generate(Context *context)
{
}
void Instruction::I64x2ExtendLowI32x4S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xc7, code);
}
void Instruction::I64x2ExtendHighI32x4S::generate(Context *context)
{
}
void Instruction::I64x2ExtendHighI32x4S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xc8, code);
}
void Instruction::I64x2ExtendLowI32x4U::generate(Context *context)
{
}
void Instruction::I64x2ExtendLowI32x4U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xc9, code);
}
void Instruction::I64x2ExtendHighI32x4U::generate(Context *context)
{
}
void Instruction::I64x2ExtendHighI32x4U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xca, code);
}
void Instruction::I64x2Shl::generate(Context *context)
{
}
void Instruction::I64x2Shl::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xcb, code);
}
void Instruction::I64x2ShrS::generate(Context *context)
{
}
void Instruction::I64x2ShrS::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xcc, code);
}
void Instruction::I64x2ShrU::generate(Context *context)
{
}
void Instruction::I64x2ShrU::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xcd, code);
}
void Instruction::I64x2Add::generate(Context *context)
{
}
void Instruction::I64x2Add::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xce, code);
}
void Instruction::I64x2Sub::generate(Context *context)
{
}
void Instruction::I64x2Sub::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xd1, code);
}
void Instruction::I64x2Mul::generate(Context *context)
{
}
void Instruction::I64x2Mul::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xd5, code);
}
void Instruction::I64x2ExtMulLowI32x4S::generate(Context *context)
{
}
void Instruction::I64x2ExtMulLowI32x4S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xdc, code);
}
void Instruction::I64x2ExtMulHighI32x4S::generate(Context *context)
{
}
void Instruction::I64x2ExtMulHighI32x4S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xdd, code);
}
void Instruction::I64x2ExtMulLowI32x4U::generate(Context *context)
{
}
void Instruction::I64x2ExtMulLowI32x4U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xde, code);
}
void Instruction::I64x2ExtMulHighI32x4U::generate(Context *context)
{
}
void Instruction::I64x2ExtMulHighI32x4U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xdf, code);
}
void Instruction::F32x4Ceil::generate(Context *context)
{
}
void Instruction::F32x4Ceil::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x67, code);
}
void Instruction::F32x4Floor::generate(Context *context)
{
}
void Instruction::F32x4Floor::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x68, code);
}
void Instruction::F32x4Trunc::generate(Context *context)
{
}
void Instruction::F32x4Trunc::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x69, code);
}
void Instruction::F32x4Nearest::generate(Context *context)
{
}
void Instruction::F32x4Nearest::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x6a, code);
}
void Instruction::F32x4Abs::generate(Context *context)
{
}
void Instruction::F32x4Abs::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xe0, code);
}
void Instruction::F32x4Neg::generate(Context *context)
{
}
void Instruction::F32x4Neg::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xe1, code);
}
void Instruction::F32x4Sqrt::generate(Context *context)
{
}
void Instruction::F32x4Sqrt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xe3, code);
}
void Instruction::F32x4Add::generate(Context *context)
{
}
void Instruction::F32x4Add::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xe4, code);
}
void Instruction::F32x4Sub::generate(Context *context)
{
}
void Instruction::F32x4Sub::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xe5, code);
}
void Instruction::F32x4Mul::generate(Context *context)
{
}
void Instruction::F32x4Mul::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xe6, code);
}
void Instruction::F32x4Div::generate(Context *context)
{
}
void Instruction::F32x4Div::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xe7, code);
}
void Instruction::F32x4Min::generate(Context *context)
{
}
void Instruction::F32x4Min::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xe8, code);
}
void Instruction::F32x4Max::generate(Context *context)
{
}
void Instruction::F32x4Max::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xe9, code);
}
void Instruction::F32x4PMin::generate(Context *context)
{
}
void Instruction::F32x4PMin::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xea, code);
}
void Instruction::F32x4PMax::generate(Context *context)
{
}
void Instruction::F32x4PMax::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xeb, code);
}
void Instruction::F64x2Ceil::generate(Context *context)
{
}
void Instruction::F64x2Ceil::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x74, code);
}
void Instruction::F64x2Floor::generate(Context *context)
{
}
void Instruction::F64x2Floor::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x75, code);
}
void Instruction::F64x2Trunc::generate(Context *context)
{
}
void Instruction::F64x2Trunc::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x7a, code);
}
void Instruction::F64x2Nearest::generate(Context *context)
{
}
void Instruction::F64x2Nearest::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x94, code);
}
void Instruction::F64x2Abs::generate(Context *context)
{
}
void Instruction::F64x2Abs::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xec, code);
}
void Instruction::F64x2Neg::generate(Context *context)
{
}
void Instruction::F64x2Neg::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xed, code);
}
void Instruction::F64x2Sqrt::generate(Context *context)
{
}
void Instruction::F64x2Sqrt::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xef, code);
}
void Instruction::F64x2Add::generate(Context *context)
{
}
void Instruction::F64x2Add::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xf0, code);
}
void Instruction::F64x2Sub::generate(Context *context)
{
}
void Instruction::F64x2Sub::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xf1, code);
}
void Instruction::F64x2Mul::generate(Context *context)
{
}
void Instruction::F64x2Mul::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xf2, code);
}
void Instruction::F64x2Div::generate(Context *context)
{
}
void Instruction::F64x2Div::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xf3, code);
}
void Instruction::F64x2Min::generate(Context *context)
{
}
void Instruction::F64x2Min::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xf4, code);
}
void Instruction::F64x2Max::generate(Context *context)
{
}
void Instruction::F64x2Max::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xf5, code);
}
void Instruction::F64x2PMin::generate(Context *context)
{
}
void Instruction::F64x2PMin::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xf6, code);
}
void Instruction::F64x2PMax::generate(Context *context)
{
}
void Instruction::F64x2PMax::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xf7, code);
}
void Instruction::I32x4TruncSatF32x4S::generate(Context *context)
{
}
void Instruction::I32x4TruncSatF32x4S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xf8, code);
}
void Instruction::I32x4TruncSatF32x4U::generate(Context *context)
{
}
void Instruction::I32x4TruncSatF32x4U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xf9, code);
}
void Instruction::F32x4ConvertI32x4S::generate(Context *context)
{
}
void Instruction::F32x4ConvertI32x4S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xfa, code);
}
void Instruction::F32x4ConvertI32x4U::generate(Context *context)
{
}
void Instruction::F32x4ConvertI32x4U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xfb, code);
}
void Instruction::I32x4TruncSatF64x2SZero::generate(Context *context)
{
}
void Instruction::I32x4TruncSatF64x2SZero::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xfc, code);
}
void Instruction::I32x4TruncSatF64x2UZero::generate(Context *context)
{
}
void Instruction::I32x4TruncSatF64x2UZero::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xfd, code);
}
void Instruction::F64x2ConvertLowI32x4S::generate(Context *context)
{
}
void Instruction::F64x2ConvertLowI32x4S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xfe, code);
}
void Instruction::F64x2ConvertLowI32x4U::generate(Context *context)
{
}
void Instruction::F64x2ConvertLowI32x4U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xff, code);
}
void Instruction::F32x4DemoteF64x2Zero::generate(Context *context)
{
}
void Instruction::F32x4DemoteF64x2Zero::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x5e, code);
}
void Instruction::F64x2PromoteLowF32x4::generate(Context *context)
{
}
void Instruction::F64x2PromoteLowF32x4::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0x5f, code);
}
void Instruction::I8x16RelaxedSwizzle::generate(Context *context)
{
}
void Instruction::I8x16RelaxedSwizzle::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xa2, code);
}
void Instruction::I32x4RelaxedTruncSatF32x4S::generate(Context *context)
{
}
void Instruction::I32x4RelaxedTruncSatF32x4S::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xa5, code);
}
void Instruction::I32x4RelaxedTruncSatF32x4U::generate(Context *context)
{
}
void Instruction::I32x4RelaxedTruncSatF32x4U::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xa6, code);
}
void Instruction::I32x4RelaxedTruncSatF64x2SZero::generate(Context *context)
{
}
void Instruction::I32x4RelaxedTruncSatF64x2SZero::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xc5, code);
}
void Instruction::I32x4RelaxedTruncSatF64x2UZero::generate(Context *context)
{
}
void Instruction::I32x4RelaxedTruncSatF64x2UZero::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xc6, code);
}
void Instruction::F32x4Fma::generate(Context *context)
{
}
void Instruction::F32x4Fma::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xaf, code);
}
void Instruction::F32x4Fms::generate(Context *context)
{
}
void Instruction::F32x4Fms::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xb0, code);
}
void Instruction::F64x2Fma::generate(Context *context)
{
}
void Instruction::F64x2Fma::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xcf, code);
}
void Instruction::F64x2Fms::generate(Context *context)
{
}
void Instruction::F64x2Fms::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xd0, code);
}
void Instruction::I8x16LaneSelect::generate(Context *context)
{
}
void Instruction::I8x16LaneSelect::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xb2, code);
}
void Instruction::I16x8LaneSelect::generate(Context *context)
{
}
void Instruction::I16x8LaneSelect::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xb3, code);
}
void Instruction::I32x4LaneSelect::generate(Context *context)
{
}
void Instruction::I32x4LaneSelect::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xd2, code);
}
void Instruction::I64x2LaneSelect::generate(Context *context)
{
}
void Instruction::I64x2LaneSelect::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xd3, code);
}
void Instruction::F32x4RelaxedMin::generate(Context *context)
{
}
void Instruction::F32x4RelaxedMin::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xb4, code);
}
void Instruction::F32x4RelaxedMax::generate(Context *context)
{
}
void Instruction::F32x4RelaxedMax::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xe2, code);
}
void Instruction::F64x2RelaxedMin::generate(Context *context)
{
}
void Instruction::F64x2RelaxedMin::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xd4, code);
}
void Instruction::F64x2RelaxedMax::generate(Context *context)
{
}
void Instruction::F64x2RelaxedMax::getByteCode(DataOutputStream *code)
{
    code->write_byte(0xfd);
    unsigned_to_leb128(0xee, code);
}

void Instruction::IfStateMent::clean()
{
    int len = if_instructions.size();
    if (len)
    {
        for (int i = 0; i < len; i++)
        {
            delete if_instructions[i];
        }
        if_instructions.clear();
    }
}

void Instruction::IfStateMent::generate(Context *context)
{
    clean();
    if_s.generate(context);
    int num_instruction = context->random->range(0, 0x10); // TODO
    for (int i = 0; i < num_instruction; i++)
    {
        Instruction *ins = CHOICE_VEC(instructions)();
        ins->generate(context);
        if_instructions.push_back(ins);
    }
}
void Instruction::IfStateMent::getByteCode(DataOutputStream *code)
{
    if_s.getByteCode(code);
    int len = if_instructions.size();
    for (int i = 0; i < len; i++)
    {
        if_instructions[i]->getByteCode(code);
    }
    end.getByteCode(code);
}

Instruction::IfStateMent::~IfStateMent()
{
    clean();
}

void Instruction::IfElseStateMent::clean()
{
    int len = if_instructions.size();
    if (len)
    {
        for (int i = 0; i < len; i++)
        {
            delete if_instructions[i];
        }
        if_instructions.clear();
    }
    len = else_instructions.size();
    if (len)
    {
        for (int i = 0; i < len; i++)
        {
            delete else_instructions[i];
        }
        else_instructions.clear();
    }
}

void Instruction::IfElseStateMent::generate(Context *context)
{
    clean();
    if_s.generate(context);
    int num_instruction = context->random->range(0, 0x10); // TODO
    for (int i = 0; i < num_instruction; i++)
    {
        Instruction *ins = CHOICE_VEC(instructions)();
        ins->generate(context);
        if_instructions.push_back(ins);
    }
    num_instruction = context->random->range(0, 0x10); // TODO
    for (int i = 0; i < num_instruction; i++)
    {
        Instruction *ins = CHOICE_VEC(instructions)();
        ins->generate(context);
        else_instructions.push_back(ins);
    }
}
void Instruction::IfElseStateMent::getByteCode(DataOutputStream *code)
{
    if_s.getByteCode(code);
    int len = if_instructions.size();
    for (int i = 0; i < len; i++)
    {
        if_instructions[i]->getByteCode(code);
    }
    len = else_instructions.size();
    for (int i = 0; i < len; i++)
    {
        else_instructions[i]->getByteCode(code);
    }
    end.getByteCode(code);
}
Instruction::IfElseStateMent::~IfElseStateMent()
{
    clean();
}
void Instruction::LoopStateMent::clean()
{
    int len = loop_instructions.size();
    if (len)
    {
        for (int i = 0; i < len; i++)
        {
            delete loop_instructions[i];
        }
        loop_instructions.clear();
    }
}

void Instruction::LoopStateMent::generate(Context *context)
{
    clean();
    loop.generate(context);
    int num_instruction = context->random->range(0, 0x10); // TODO
    for (int i = 0; i < num_instruction; i++)
    {
        Instruction *ins = CHOICE_VEC(instructions)();
        ins->generate(context);
        loop_instructions.push_back(ins);
    }
}
void Instruction::LoopStateMent::getByteCode(DataOutputStream *code)
{
    loop.getByteCode(code);
    int len = loop_instructions.size();
    for (int i = 0; i < len; i++)
    {
        loop_instructions[i]->getByteCode(code);
    }
    end.getByteCode(code);
}
Instruction::LoopStateMent::~LoopStateMent()
{
    clean();
}
void Instruction::BlockStateMent::clean()
{
    int len = block_instructions.size();
    if (len)
    {
        for (int i = 0; i < len; i++)
        {
            delete block_instructions[i];
        }
        block_instructions.clear();
    }
}

void Instruction::BlockStateMent::generate(Context *context)
{
    clean();
    block.generate(context);
    int num_instruction = context->random->range(0, 0x10); // TODO
    for (int i = 0; i < num_instruction; i++)
    {
        Instruction *ins = CHOICE_VEC(instructions)();
        ins->generate(context);
        block_instructions.push_back(ins);
    }
}
void Instruction::BlockStateMent::getByteCode(DataOutputStream *code)
{
    block.getByteCode(code);
    int len = block_instructions.size();
    for (int i = 0; i < len; i++)
    {
        block_instructions[i]->getByteCode(code);
    }
    end.getByteCode(code);
}
Instruction::BlockStateMent::~BlockStateMent()
{
    clean();
}