#ifndef SECTION_LIST_H
#define SECTION_LIST_H

#include <vector>
#include "section.h"
#include "object.h"
#include "instruction.h"

#define HANDLE_SECTION(clazz) ((Sections::Section * (*)(void)) instanceObj<clazz>)
#define ADD_SECTION_LIST(clazz) (sections_list.push_back(HANDLE_SECTION(clazz)));

#define HANDLE_INSTRUCTION(clazz) ((Instruction * (*)(void)) instanceObj<clazz>)
#define ADD_BLOCK_INSTRUCTION_LIST(clazz) (block_instructions.push_back(HANDLE_INSTRUCTION(clazz)));
#define ADD_INSTRUCTION_LIST(clazz) (instructions.push_back(HANDLE_INSTRUCTION(clazz)));
#define ADD_CONST_INSTRUCTION_LIST(clazz) (const_instructions.push_back(HANDLE_INSTRUCTION(clazz)));

#define ADD_IMPORT_FUNC(name, module) imports_function[name] = module; imports_function_name.push_back(name);

namespace Sections
{
    void initSectionsList();
    void initImportsFunction();
}

namespace Instruction
{
    void initInstructionsList();
}
void initList();

#endif