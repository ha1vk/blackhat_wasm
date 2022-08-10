#include "global_classes_list.h"
#include "custom_section.h"
#include "type_section.h"
#include "import_section.h"
#include "function_section.h"
#include "table_section.h"
#include "memory_section.h"
#include "global_section.h"
#include "export_section.h"
#include "start_section.h"
#include "elem_section.h"
#include "code_section.h"
#include "data_section.h"

namespace Sections
{
    vector<Section *(*)()> sections_list;
    void initSectionsList()
    {
        // ADD_SECTION_LIST(CustomSection)
        ADD_SECTION_LIST(TypeSection)
        ADD_SECTION_LIST(ImportSection)
        ADD_SECTION_LIST(FunctionSection)
        ADD_SECTION_LIST(TableSection)
        ADD_SECTION_LIST(MemorySection)
        ADD_SECTION_LIST(GlobalSection)
        ADD_SECTION_LIST(ExportSection)
        ADD_SECTION_LIST(StartSection)
        ADD_SECTION_LIST(ElemSection)
        ADD_SECTION_LIST(DataCountSection)
        ADD_SECTION_LIST(CodeSection)
        ADD_SECTION_LIST(DataSection)
    }

    map<string, string> imports_function;
    vector<string> imports_function_name;

    void initImportsFunction()
    {
        ADD_IMPORT_FUNC("args_get","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("args_sizes_get","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("environ_get","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("environ_sizes_get","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("clock_res_get","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("clock_time_get","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_advise","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_allocate","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_close","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_datasync","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_fdstat_get","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_fdstat_set_flags","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_fdstat_set_rights","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_filestat_get","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_filestat_set_size","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_filestat_set_times","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_pread","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_prestat_get","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_prestat_dir_name","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_pwrite","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_read","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_readdir","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_renumber","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_seek","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_sync","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_tell","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("fd_write","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("path_create_directory","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("path_filestat_get","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("path_filestat_set_times","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("path_link","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("path_open","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("path_readlink","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("path_remove_directory","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("path_rename","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("path_symlink","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("path_unlink_file","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("poll_oneoff","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("proc_exit","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("proc_raise","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sched_yield","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("random_get","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_open","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_bind","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_connect","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_listen","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_accept","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_recv","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_send","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_shutdown","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_getsockopt","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_setsockopt","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_getlocaladdr","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_getpeeraddr","wasi_snapshot_preview1")
        ADD_IMPORT_FUNC("sock_getaddrinfo","wasi_snapshot_preview1")
    }
}
namespace Instruction
{
    vector<Instruction *(*)(void)> block_instructions;
    vector<Instruction *(*)(void)> instructions;
    vector<Instruction *(*)(void)> const_instructions;
    void initInstructionsList()
    {
        ADD_INSTRUCTION_LIST(Nop)
        ADD_INSTRUCTION_LIST(BlockStateMent)
        ADD_INSTRUCTION_LIST(LoopStateMent)
        ADD_INSTRUCTION_LIST(IfStateMent)
        ADD_INSTRUCTION_LIST(IfElseStateMent)
        // ADD_INSTRUCTION_LIST(Try)
        // ADD_INSTRUCTION_LIST(Delegate)
        // ADD_INSTRUCTION_LIST(Catch)
        // ADD_INSTRUCTION_LIST(CatchAll)
        //  ADD_INSTRUCTION_LIST(End)
        ADD_INSTRUCTION_LIST(Br)
        ADD_INSTRUCTION_LIST(BrIf)
        ADD_INSTRUCTION_LIST(BrTable)
        ADD_INSTRUCTION_LIST(Return)
        ADD_INSTRUCTION_LIST(Call)
        ADD_INSTRUCTION_LIST(CallIndirect)
        // ADD_INSTRUCTION_LIST(Throw)
        // ADD_INSTRUCTION_LIST(Rethrow)
        ADD_INSTRUCTION_LIST(Drop)
        ADD_INSTRUCTION_LIST(Select)
        ADD_INSTRUCTION_LIST(LocalGet)
        ADD_INSTRUCTION_LIST(LocalSet)
        ADD_INSTRUCTION_LIST(LocalTee)
        ADD_INSTRUCTION_LIST(GlobalGet)
        ADD_INSTRUCTION_LIST(GlobalSet)
        ADD_INSTRUCTION_LIST(I32Load)
        ADD_INSTRUCTION_LIST(I64Load)
        ADD_INSTRUCTION_LIST(F32Load)
        ADD_INSTRUCTION_LIST(F64Load)
        ADD_INSTRUCTION_LIST(I32Load8_S)
        ADD_INSTRUCTION_LIST(I32Load8_U)
        ADD_INSTRUCTION_LIST(I32Load16_S)
        ADD_INSTRUCTION_LIST(I32Load16_U)
        ADD_INSTRUCTION_LIST(I64Load8_S)
        ADD_INSTRUCTION_LIST(I64Load8_U)
        ADD_INSTRUCTION_LIST(I64Load16_S)
        ADD_INSTRUCTION_LIST(I64Load16_U)
        ADD_INSTRUCTION_LIST(I64Load32_S)
        ADD_INSTRUCTION_LIST(I64Load32_U)
        ADD_INSTRUCTION_LIST(I32Store)
        ADD_INSTRUCTION_LIST(I64Store)
        ADD_INSTRUCTION_LIST(F32Store)
        ADD_INSTRUCTION_LIST(F64Store)
        ADD_INSTRUCTION_LIST(I32Store8)
        ADD_INSTRUCTION_LIST(I32Store16)
        ADD_INSTRUCTION_LIST(I64Store8)
        ADD_INSTRUCTION_LIST(I64Store16)
        ADD_INSTRUCTION_LIST(I64Store32)
        ADD_INSTRUCTION_LIST(MemorySize)
        ADD_INSTRUCTION_LIST(MemoryGrow)
        ADD_INSTRUCTION_LIST(MemoryInit)
        ADD_INSTRUCTION_LIST(DataDrop)
        ADD_INSTRUCTION_LIST(MemoryCopy)
        ADD_INSTRUCTION_LIST(MemoryFill)
        ADD_INSTRUCTION_LIST(I32Const)
        ADD_INSTRUCTION_LIST(I64Const)
        ADD_INSTRUCTION_LIST(F32Const)
        ADD_INSTRUCTION_LIST(F64Const)
        ADD_INSTRUCTION_LIST(I32Eqz)
        ADD_INSTRUCTION_LIST(I32Eq)
        ADD_INSTRUCTION_LIST(I32Ne)
        ADD_INSTRUCTION_LIST(I32LtS)
        ADD_INSTRUCTION_LIST(I32LtU)
        ADD_INSTRUCTION_LIST(I32GtS)
        ADD_INSTRUCTION_LIST(I32GtU)
        ADD_INSTRUCTION_LIST(I32LeS)
        ADD_INSTRUCTION_LIST(I32LeU)
        ADD_INSTRUCTION_LIST(I32GeS)
        ADD_INSTRUCTION_LIST(I32GeU)
        ADD_INSTRUCTION_LIST(I64Eqz)
        ADD_INSTRUCTION_LIST(I64Eq)
        ADD_INSTRUCTION_LIST(I64Ne)
        ADD_INSTRUCTION_LIST(I64LtS)
        ADD_INSTRUCTION_LIST(I64LtU)
        ADD_INSTRUCTION_LIST(I64GtS)
        ADD_INSTRUCTION_LIST(I64GtU)
        ADD_INSTRUCTION_LIST(I64LeS)
        ADD_INSTRUCTION_LIST(I64LeU)
        ADD_INSTRUCTION_LIST(I64GeS)
        ADD_INSTRUCTION_LIST(I64GeU)
        ADD_INSTRUCTION_LIST(F32Eq)
        ADD_INSTRUCTION_LIST(F32Ne)
        ADD_INSTRUCTION_LIST(F32Lt)
        ADD_INSTRUCTION_LIST(F32Gt)
        ADD_INSTRUCTION_LIST(F32Le)
        ADD_INSTRUCTION_LIST(F32Ge)
        ADD_INSTRUCTION_LIST(F64Eq)
        ADD_INSTRUCTION_LIST(F64Ne)
        ADD_INSTRUCTION_LIST(F64Lt)
        ADD_INSTRUCTION_LIST(F64Gt)
        ADD_INSTRUCTION_LIST(F64Le)
        ADD_INSTRUCTION_LIST(F64Ge)
        ADD_INSTRUCTION_LIST(I32Clz)
        ADD_INSTRUCTION_LIST(I32Ctz)
        ADD_INSTRUCTION_LIST(I32Popcnt)
        ADD_INSTRUCTION_LIST(I32Add)
        ADD_INSTRUCTION_LIST(I32Sub)
        ADD_INSTRUCTION_LIST(I32Mul)
        ADD_INSTRUCTION_LIST(I32DivS)
        ADD_INSTRUCTION_LIST(I32DivU)
        ADD_INSTRUCTION_LIST(I32RemS)
        ADD_INSTRUCTION_LIST(I32RemU)
        ADD_INSTRUCTION_LIST(I32And)
        ADD_INSTRUCTION_LIST(I32Or)
        ADD_INSTRUCTION_LIST(I32Xor)
        ADD_INSTRUCTION_LIST(I32Shl)
        ADD_INSTRUCTION_LIST(I32ShrS)
        ADD_INSTRUCTION_LIST(I32ShrU)
        ADD_INSTRUCTION_LIST(I32Rotl)
        ADD_INSTRUCTION_LIST(I32Rotr)
        ADD_INSTRUCTION_LIST(I64Clz)
        ADD_INSTRUCTION_LIST(I64Ctz)
        ADD_INSTRUCTION_LIST(I64Popcnt)
        ADD_INSTRUCTION_LIST(I64Add)
        ADD_INSTRUCTION_LIST(I64Sub)
        ADD_INSTRUCTION_LIST(I64Mul)
        ADD_INSTRUCTION_LIST(I64DivS)
        ADD_INSTRUCTION_LIST(I64DivU)
        ADD_INSTRUCTION_LIST(I64RemS)
        ADD_INSTRUCTION_LIST(I64RemU)
        ADD_INSTRUCTION_LIST(I64And)
        ADD_INSTRUCTION_LIST(I64Or)
        ADD_INSTRUCTION_LIST(I64Xor)
        ADD_INSTRUCTION_LIST(I64Shl)
        ADD_INSTRUCTION_LIST(I64ShrS)
        ADD_INSTRUCTION_LIST(I64ShrU)
        ADD_INSTRUCTION_LIST(I64Rotl)
        ADD_INSTRUCTION_LIST(I64Rotr)
        ADD_INSTRUCTION_LIST(F32Abs)
        ADD_INSTRUCTION_LIST(F32Neg)
        ADD_INSTRUCTION_LIST(F32Ceil)
        ADD_INSTRUCTION_LIST(F32Floor)
        ADD_INSTRUCTION_LIST(F32Trunc)
        ADD_INSTRUCTION_LIST(F32Nearest)
        ADD_INSTRUCTION_LIST(F32Sqrt)
        ADD_INSTRUCTION_LIST(F32Add)
        ADD_INSTRUCTION_LIST(F32Sub)
        ADD_INSTRUCTION_LIST(F32Mul)
        ADD_INSTRUCTION_LIST(F32Div)
        ADD_INSTRUCTION_LIST(F32Min)
        ADD_INSTRUCTION_LIST(F32Max)
        ADD_INSTRUCTION_LIST(F32Copysign)
        ADD_INSTRUCTION_LIST(F64Abs)
        ADD_INSTRUCTION_LIST(F64Neg)
        ADD_INSTRUCTION_LIST(F64Ceil)
        ADD_INSTRUCTION_LIST(F64Floor)
        ADD_INSTRUCTION_LIST(F64Trunc)
        ADD_INSTRUCTION_LIST(F64Nearest)
        ADD_INSTRUCTION_LIST(F64Sqrt)
        ADD_INSTRUCTION_LIST(F64Add)
        ADD_INSTRUCTION_LIST(F64Sub)
        ADD_INSTRUCTION_LIST(F64Mul)
        ADD_INSTRUCTION_LIST(F64Div)
        ADD_INSTRUCTION_LIST(F64Min)
        ADD_INSTRUCTION_LIST(F64Max)
        ADD_INSTRUCTION_LIST(F64Copysign)
        ADD_INSTRUCTION_LIST(I32WrapI64)
        ADD_INSTRUCTION_LIST(I32TruncF32S)
        ADD_INSTRUCTION_LIST(I32TruncF32U)
        ADD_INSTRUCTION_LIST(I32TruncF64S)
        ADD_INSTRUCTION_LIST(I32TruncF64U)
        ADD_INSTRUCTION_LIST(I64ExtendI32S)
        ADD_INSTRUCTION_LIST(I64ExtendI32U)
        ADD_INSTRUCTION_LIST(I64TruncF32S)
        ADD_INSTRUCTION_LIST(I64TruncF32U)
        ADD_INSTRUCTION_LIST(I64TruncF64S)
        ADD_INSTRUCTION_LIST(I64TruncF64U)
        ADD_INSTRUCTION_LIST(F32ConvertI32S)
        ADD_INSTRUCTION_LIST(F32ConvertI32U)
        ADD_INSTRUCTION_LIST(F32ConvertI64S)
        ADD_INSTRUCTION_LIST(F32ConvertI64U)
        ADD_INSTRUCTION_LIST(F32DemoteF64)
        ADD_INSTRUCTION_LIST(F64ConvertI32S)
        ADD_INSTRUCTION_LIST(F64ConvertI32U)
        ADD_INSTRUCTION_LIST(F64ConvertI64S)
        ADD_INSTRUCTION_LIST(F64ConvertI64U)
        ADD_INSTRUCTION_LIST(F64PromoteF32)
        ADD_INSTRUCTION_LIST(I32ReinterpretF32)
        ADD_INSTRUCTION_LIST(I64ReinterpretF64)
        ADD_INSTRUCTION_LIST(F32ReinterpretI32)
        ADD_INSTRUCTION_LIST(F64ReinterpretI64)
        ADD_INSTRUCTION_LIST(I32Extend8S)
        ADD_INSTRUCTION_LIST(I32Extend16S)
        ADD_INSTRUCTION_LIST(I64Extend8S)
        ADD_INSTRUCTION_LIST(I64Extend16S)
        ADD_INSTRUCTION_LIST(I64Extend32S)
        ADD_INSTRUCTION_LIST(I32TruncSatF32S)
        ADD_INSTRUCTION_LIST(I32TruncSatF32U)
        ADD_INSTRUCTION_LIST(I32TruncSatF64S)
        ADD_INSTRUCTION_LIST(I32TruncSatF64U)
        ADD_INSTRUCTION_LIST(I64TruncSatF32S)
        ADD_INSTRUCTION_LIST(I64TruncSatF32U)
        ADD_INSTRUCTION_LIST(I64TruncSatF64S)
        ADD_INSTRUCTION_LIST(I64TruncSatF64U)
        ADD_INSTRUCTION_LIST(TypedSelect)
        ADD_INSTRUCTION_LIST(RefNull)
        ADD_INSTRUCTION_LIST(RefIsNull)
        ADD_INSTRUCTION_LIST(RefFunc)
        ADD_INSTRUCTION_LIST(TableInit)
        ADD_INSTRUCTION_LIST(ElemDrop)
        ADD_INSTRUCTION_LIST(TableFill)
        ADD_INSTRUCTION_LIST(TableSet)
        ADD_INSTRUCTION_LIST(TableGet)
        ADD_INSTRUCTION_LIST(TableGrow)
        ADD_INSTRUCTION_LIST(TableSize)
        ADD_INSTRUCTION_LIST(TableCopy)
        ADD_INSTRUCTION_LIST(V128Load)
        ADD_INSTRUCTION_LIST(V128Load8x8S)
        ADD_INSTRUCTION_LIST(V128Load8x8U)
        ADD_INSTRUCTION_LIST(V128Load16x4S)
        ADD_INSTRUCTION_LIST(V128Load16x4U)
        ADD_INSTRUCTION_LIST(V128Load32x2S)
        ADD_INSTRUCTION_LIST(V128Load32x2U)
        ADD_INSTRUCTION_LIST(V128Load8Splat)
        ADD_INSTRUCTION_LIST(V128Load16Splat)
        ADD_INSTRUCTION_LIST(V128Load32Splat)
        ADD_INSTRUCTION_LIST(V128Load64Splat)
        ADD_INSTRUCTION_LIST(V128Load32Zero)
        ADD_INSTRUCTION_LIST(V128Load64Zero)
        ADD_INSTRUCTION_LIST(V128Store)
        ADD_INSTRUCTION_LIST(V128Load8Lane)
        ADD_INSTRUCTION_LIST(V128Load16Lane)
        ADD_INSTRUCTION_LIST(V128Load32Lane)
        ADD_INSTRUCTION_LIST(V128Load64Lane)
        ADD_INSTRUCTION_LIST(V128Store8Lane)
        ADD_INSTRUCTION_LIST(V128Store16Lane)
        ADD_INSTRUCTION_LIST(V128Store32Lane)
        ADD_INSTRUCTION_LIST(V128Store64Lane)
        ADD_INSTRUCTION_LIST(V128Const)
        ADD_INSTRUCTION_LIST(I8x16Shuffle)
        ADD_INSTRUCTION_LIST(I8x16ExtractLaneS)
        ADD_INSTRUCTION_LIST(I8x16ExtractLaneU)
        ADD_INSTRUCTION_LIST(I8x16ReplaceLane)
        ADD_INSTRUCTION_LIST(I16x8ExtractLaneS)
        ADD_INSTRUCTION_LIST(I16x8ExtractLaneU)
        ADD_INSTRUCTION_LIST(I16x8ReplaceLane)
        ADD_INSTRUCTION_LIST(I32x4ExtractLane)
        ADD_INSTRUCTION_LIST(I32x4ReplaceLane)
        ADD_INSTRUCTION_LIST(I64x2ExtractLane)
        ADD_INSTRUCTION_LIST(I64x2ReplaceLane)
        ADD_INSTRUCTION_LIST(F32x4ExtractLane)
        ADD_INSTRUCTION_LIST(F32x4ReplaceLane)
        ADD_INSTRUCTION_LIST(F64x2ExtractLane)
        ADD_INSTRUCTION_LIST(F64x2ReplaceLane)
        ADD_INSTRUCTION_LIST(I8x16Swizzle)
        ADD_INSTRUCTION_LIST(I8x16Splat)
        ADD_INSTRUCTION_LIST(I16x8Splat)
        ADD_INSTRUCTION_LIST(I32x4Splat)
        ADD_INSTRUCTION_LIST(I64x2Splat)
        ADD_INSTRUCTION_LIST(F32x4Splat)
        ADD_INSTRUCTION_LIST(F64x2Splat)
        ADD_INSTRUCTION_LIST(I8x16Eq)
        ADD_INSTRUCTION_LIST(I8x16Ne)
        ADD_INSTRUCTION_LIST(I8x16LtS)
        ADD_INSTRUCTION_LIST(I8x16LtU)
        ADD_INSTRUCTION_LIST(I8x16GtS)
        ADD_INSTRUCTION_LIST(I8x16GtU)
        ADD_INSTRUCTION_LIST(I8x16LeS)
        ADD_INSTRUCTION_LIST(I8x16LeU)
        ADD_INSTRUCTION_LIST(I8x16GeS)
        ADD_INSTRUCTION_LIST(I8x16GeU)
        ADD_INSTRUCTION_LIST(I16x8Eq)
        ADD_INSTRUCTION_LIST(I16x8Ne)
        ADD_INSTRUCTION_LIST(I16x8LtS)
        ADD_INSTRUCTION_LIST(I16x8LtU)
        ADD_INSTRUCTION_LIST(I16x8GtS)
        ADD_INSTRUCTION_LIST(I16x8GtU)
        ADD_INSTRUCTION_LIST(I16x8LeS)
        ADD_INSTRUCTION_LIST(I16x8LeU)
        ADD_INSTRUCTION_LIST(I16x8GeS)
        ADD_INSTRUCTION_LIST(I16x8GeU)
        ADD_INSTRUCTION_LIST(I32x4Eq)
        ADD_INSTRUCTION_LIST(I32x4Ne)
        ADD_INSTRUCTION_LIST(I32x4LtS)
        ADD_INSTRUCTION_LIST(I32x4LtU)
        ADD_INSTRUCTION_LIST(I32x4GtS)
        ADD_INSTRUCTION_LIST(I32x4GtU)
        ADD_INSTRUCTION_LIST(I32x4LeS)
        ADD_INSTRUCTION_LIST(I32x4LeU)
        ADD_INSTRUCTION_LIST(I32x4GeS)
        ADD_INSTRUCTION_LIST(I32x4GeU)
        ADD_INSTRUCTION_LIST(I64x2Eq)
        ADD_INSTRUCTION_LIST(I64x2Ne)
        ADD_INSTRUCTION_LIST(I64x2LtS)
        ADD_INSTRUCTION_LIST(I64x2GtS)
        ADD_INSTRUCTION_LIST(I64x2LeS)
        ADD_INSTRUCTION_LIST(I64x2GeS)
        ADD_INSTRUCTION_LIST(F32x4Eq)
        ADD_INSTRUCTION_LIST(F32x4Ne)
        ADD_INSTRUCTION_LIST(F32x4Lt)
        ADD_INSTRUCTION_LIST(F32x4Gt)
        ADD_INSTRUCTION_LIST(F32x4Le)
        ADD_INSTRUCTION_LIST(F32x4Ge)
        ADD_INSTRUCTION_LIST(F64x2Eq)
        ADD_INSTRUCTION_LIST(F64x2Ne)
        ADD_INSTRUCTION_LIST(F64x2Lt)
        ADD_INSTRUCTION_LIST(F64x2Gt)
        ADD_INSTRUCTION_LIST(F64x2Le)
        ADD_INSTRUCTION_LIST(F64x2Ge)
        ADD_INSTRUCTION_LIST(V128Not)
        ADD_INSTRUCTION_LIST(V128And)
        ADD_INSTRUCTION_LIST(V128AndNot)
        ADD_INSTRUCTION_LIST(V128Or)
        ADD_INSTRUCTION_LIST(V128Xor)
        ADD_INSTRUCTION_LIST(V128Bitselect)
        ADD_INSTRUCTION_LIST(V128AnyTrue)
        ADD_INSTRUCTION_LIST(I8x16Abs)
        ADD_INSTRUCTION_LIST(I8x16Neg)
        ADD_INSTRUCTION_LIST(I8x16Popcnt)
        ADD_INSTRUCTION_LIST(I8x16AllTrue)
        ADD_INSTRUCTION_LIST(I8x16Bitmask)
        ADD_INSTRUCTION_LIST(I8x16NarrowI16x8S)
        ADD_INSTRUCTION_LIST(I8x16NarrowI16x8U)
        ADD_INSTRUCTION_LIST(I8x16Shl)
        ADD_INSTRUCTION_LIST(I8x16ShrS)
        ADD_INSTRUCTION_LIST(I8x16ShrU)
        ADD_INSTRUCTION_LIST(I8x16Add)
        ADD_INSTRUCTION_LIST(I8x16AddSatS)
        ADD_INSTRUCTION_LIST(I8x16AddSatU)
        ADD_INSTRUCTION_LIST(I8x16Sub)
        ADD_INSTRUCTION_LIST(I8x16SubSatS)
        ADD_INSTRUCTION_LIST(I8x16SubSatU)
        ADD_INSTRUCTION_LIST(I8x16MinS)
        ADD_INSTRUCTION_LIST(I8x16MinU)
        ADD_INSTRUCTION_LIST(I8x16MaxS)
        ADD_INSTRUCTION_LIST(I8x16MaxU)
        ADD_INSTRUCTION_LIST(I8x16RoundingAverageU)
        ADD_INSTRUCTION_LIST(I16x8ExtAddPairwiseI8x16S)
        ADD_INSTRUCTION_LIST(I16x8ExtAddPairwiseI8x16U)
        ADD_INSTRUCTION_LIST(I16x8Abs)
        ADD_INSTRUCTION_LIST(I16x8Neg)
        ADD_INSTRUCTION_LIST(I16x8Q15MulrSatS)
        ADD_INSTRUCTION_LIST(I16x8AllTrue)
        ADD_INSTRUCTION_LIST(I16x8Bitmask)
        ADD_INSTRUCTION_LIST(I16x8NarrowI32x4S)
        ADD_INSTRUCTION_LIST(I16x8NarrowI32x4U)
        ADD_INSTRUCTION_LIST(I16x8ExtendLowI8x16S)
        ADD_INSTRUCTION_LIST(I16x8ExtendHighI8x16S)
        ADD_INSTRUCTION_LIST(I16x8ExtendLowI8x16U)
        ADD_INSTRUCTION_LIST(I16x8ExtendHighI8x16U)
        ADD_INSTRUCTION_LIST(I16x8Shl)
        ADD_INSTRUCTION_LIST(I16x8ShrS)
        ADD_INSTRUCTION_LIST(I16x8ShrU)
        ADD_INSTRUCTION_LIST(I16x8Add)
        ADD_INSTRUCTION_LIST(I16x8AddSatS)
        ADD_INSTRUCTION_LIST(I16x8AddSatU)
        ADD_INSTRUCTION_LIST(I16x8Sub)
        ADD_INSTRUCTION_LIST(I16x8SubSatS)
        ADD_INSTRUCTION_LIST(I16x8SubSatU)
        ADD_INSTRUCTION_LIST(I16x8Mul)
        ADD_INSTRUCTION_LIST(I16x8MinS)
        ADD_INSTRUCTION_LIST(I16x8MinU)
        ADD_INSTRUCTION_LIST(I16x8MaxS)
        ADD_INSTRUCTION_LIST(I16x8MaxU)
        ADD_INSTRUCTION_LIST(I16x8RoundingAverageU)
        ADD_INSTRUCTION_LIST(I16x8ExtMulLowI8x16S)
        ADD_INSTRUCTION_LIST(I16x8ExtMulHighI8x16S)
        ADD_INSTRUCTION_LIST(I16x8ExtMulLowI8x16U)
        ADD_INSTRUCTION_LIST(I16x8ExtMulHighI8x16U)
        ADD_INSTRUCTION_LIST(I32x4ExtAddPairwiseI16x8S)
        ADD_INSTRUCTION_LIST(I32x4ExtAddPairwiseI16x8U)
        ADD_INSTRUCTION_LIST(I32x4Abs)
        ADD_INSTRUCTION_LIST(I32x4Neg)
        ADD_INSTRUCTION_LIST(I32x4AllTrue)
        ADD_INSTRUCTION_LIST(I32x4Bitmask)
        ADD_INSTRUCTION_LIST(I32x4ExtendLowI16x8S)
        ADD_INSTRUCTION_LIST(I32x4ExtendHighI16x8S)
        ADD_INSTRUCTION_LIST(I32x4ExtendLowI16x8U)
        ADD_INSTRUCTION_LIST(I32x4ExtendHighI16x8U)
        ADD_INSTRUCTION_LIST(I32x4Shl)
        ADD_INSTRUCTION_LIST(I32x4ShrS)
        ADD_INSTRUCTION_LIST(I32x4ShrU)
        ADD_INSTRUCTION_LIST(I32x4Add)
        ADD_INSTRUCTION_LIST(I32x4Sub)
        ADD_INSTRUCTION_LIST(I32x4Mul)
        ADD_INSTRUCTION_LIST(I32x4MinS)
        ADD_INSTRUCTION_LIST(I32x4MinU)
        ADD_INSTRUCTION_LIST(I32x4MaxS)
        ADD_INSTRUCTION_LIST(I32x4MaxU)
        ADD_INSTRUCTION_LIST(I32x4DotI16x8S)
        ADD_INSTRUCTION_LIST(I32x4ExtMulLowI16x8S)
        ADD_INSTRUCTION_LIST(I32x4ExtMulHighI16x8S)
        ADD_INSTRUCTION_LIST(I32x4ExtMulLowI16x8U)
        ADD_INSTRUCTION_LIST(I32x4ExtMulHighI16x8U)
        ADD_INSTRUCTION_LIST(I64x2Abs)
        ADD_INSTRUCTION_LIST(I64x2Neg)
        ADD_INSTRUCTION_LIST(I64x2AllTrue)
        ADD_INSTRUCTION_LIST(I64x2Bitmask)
        ADD_INSTRUCTION_LIST(I64x2ExtendLowI32x4S)
        ADD_INSTRUCTION_LIST(I64x2ExtendHighI32x4S)
        ADD_INSTRUCTION_LIST(I64x2ExtendLowI32x4U)
        ADD_INSTRUCTION_LIST(I64x2ExtendHighI32x4U)
        ADD_INSTRUCTION_LIST(I64x2Shl)
        ADD_INSTRUCTION_LIST(I64x2ShrS)
        ADD_INSTRUCTION_LIST(I64x2ShrU)
        ADD_INSTRUCTION_LIST(I64x2Add)
        ADD_INSTRUCTION_LIST(I64x2Sub)
        ADD_INSTRUCTION_LIST(I64x2Mul)
        ADD_INSTRUCTION_LIST(I64x2ExtMulLowI32x4S)
        ADD_INSTRUCTION_LIST(I64x2ExtMulHighI32x4S)
        ADD_INSTRUCTION_LIST(I64x2ExtMulLowI32x4U)
        ADD_INSTRUCTION_LIST(I64x2ExtMulHighI32x4U)
        ADD_INSTRUCTION_LIST(F32x4Ceil)
        ADD_INSTRUCTION_LIST(F32x4Floor)
        ADD_INSTRUCTION_LIST(F32x4Trunc)
        ADD_INSTRUCTION_LIST(F32x4Nearest)
        ADD_INSTRUCTION_LIST(F32x4Abs)
        ADD_INSTRUCTION_LIST(F32x4Neg)
        ADD_INSTRUCTION_LIST(F32x4Sqrt)
        ADD_INSTRUCTION_LIST(F32x4Add)
        ADD_INSTRUCTION_LIST(F32x4Sub)
        ADD_INSTRUCTION_LIST(F32x4Mul)
        ADD_INSTRUCTION_LIST(F32x4Div)
        ADD_INSTRUCTION_LIST(F32x4Min)
        ADD_INSTRUCTION_LIST(F32x4Max)
        ADD_INSTRUCTION_LIST(F32x4PMin)
        ADD_INSTRUCTION_LIST(F32x4PMax)
        ADD_INSTRUCTION_LIST(F64x2Ceil)
        ADD_INSTRUCTION_LIST(F64x2Floor)
        ADD_INSTRUCTION_LIST(F64x2Trunc)
        ADD_INSTRUCTION_LIST(F64x2Nearest)
        ADD_INSTRUCTION_LIST(F64x2Abs)
        ADD_INSTRUCTION_LIST(F64x2Neg)
        ADD_INSTRUCTION_LIST(F64x2Sqrt)
        ADD_INSTRUCTION_LIST(F64x2Add)
        ADD_INSTRUCTION_LIST(F64x2Sub)
        ADD_INSTRUCTION_LIST(F64x2Mul)
        ADD_INSTRUCTION_LIST(F64x2Div)
        ADD_INSTRUCTION_LIST(F64x2Min)
        ADD_INSTRUCTION_LIST(F64x2Max)
        ADD_INSTRUCTION_LIST(F64x2PMin)
        ADD_INSTRUCTION_LIST(F64x2PMax)
        ADD_INSTRUCTION_LIST(I32x4TruncSatF32x4S)
        ADD_INSTRUCTION_LIST(I32x4TruncSatF32x4U)
        ADD_INSTRUCTION_LIST(F32x4ConvertI32x4S)
        ADD_INSTRUCTION_LIST(F32x4ConvertI32x4U)
        ADD_INSTRUCTION_LIST(I32x4TruncSatF64x2SZero)
        ADD_INSTRUCTION_LIST(I32x4TruncSatF64x2UZero)
        ADD_INSTRUCTION_LIST(F64x2ConvertLowI32x4S)
        ADD_INSTRUCTION_LIST(F64x2ConvertLowI32x4U)
        ADD_INSTRUCTION_LIST(F32x4DemoteF64x2Zero)
        ADD_INSTRUCTION_LIST(F64x2PromoteLowF32x4)
        // ADD_INSTRUCTION_LIST(I8x16RelaxedSwizzle)
        // ADD_INSTRUCTION_LIST(I32x4RelaxedTruncSatF32x4S)
        // ADD_INSTRUCTION_LIST(I32x4RelaxedTruncSatF32x4U)
        // ADD_INSTRUCTION_LIST(I32x4RelaxedTruncSatF64x2SZero)
        // ADD_INSTRUCTION_LIST(I32x4RelaxedTruncSatF64x2UZero)
        // ADD_INSTRUCTION_LIST(F32x4Fma)
        // ADD_INSTRUCTION_LIST(F32x4Fms)
        // ADD_INSTRUCTION_LIST(F64x2Fma)
        // ADD_INSTRUCTION_LIST(F64x2Fms)
        // ADD_INSTRUCTION_LIST(I8x16LaneSelect)
        // ADD_INSTRUCTION_LIST(I16x8LaneSelect)
        // ADD_INSTRUCTION_LIST(I32x4LaneSelect)
        // ADD_INSTRUCTION_LIST(I64x2LaneSelect)
        // ADD_INSTRUCTION_LIST(F32x4RelaxedMin)
        // ADD_INSTRUCTION_LIST(F32x4RelaxedMax)
        // ADD_INSTRUCTION_LIST(F64x2RelaxedMin)
        // ADD_INSTRUCTION_LIST(F64x2RelaxedMax)

        // const
        ADD_CONST_INSTRUCTION_LIST(I32Const)
        ADD_CONST_INSTRUCTION_LIST(I64Const)
        ADD_CONST_INSTRUCTION_LIST(F32Const)
        ADD_CONST_INSTRUCTION_LIST(F64Const)
        ADD_CONST_INSTRUCTION_LIST(V128Const)
    }
}
void initList()
{
    Sections::initSectionsList();
    Sections::initImportsFunction();
    Instruction::initInstructionsList();
}