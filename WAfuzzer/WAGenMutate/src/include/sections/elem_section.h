#ifndef ELEM_H
#define ELEM_H

#include "section.h"
#include "instruction.h"
#include "values.h"

namespace Sections
{
    using namespace Value;

    class Elements
    {
    public:
        enum ElementsID
        {
            /// A sequences of references to functions by their indices.
            FunctionsID,
            /// A sequence of reference expressions.
            ExpressionsID,
        };
        virtual ElementsID id() = 0;
        virtual void generate(Context *context) = 0;
        virtual void getEncode(DataOutputStream *out, ValType element_type) = 0;
        virtual ~Elements() {}
    };

    class Functions : public Elements
    {
    private:
        vector<u32Value> fs;

    public:
        ElementsID id();
        void generate(Context *context);
        void getEncode(DataOutputStream *out, ValType element_type = I32);
    };
    class Expressions : public Elements
    {
    public:
        enum ElementID
        {
            /// A null reference.
            NullID,
            /// A `ref.func n`.
            FuncID,
        };

    private:
        vector<ElementID> e;

    public:
        ElementsID id();
        void generate(Context *context);
        void getEncode(DataOutputStream *out, ValType element_type);
    };

    class ElemSegType : public TypeEx
    {
    public:
        enum ElementMode
        {
            /// A passive element segment.
            ///
            /// Passive segments are part of the bulk memory proposal.
            Passive,
            /// A declared element segment.
            ///
            /// Declared segments are part of the bulk memory proposal.
            Declared,
            /// An active element segment.
            Active
        };

    private:
        ElementMode mode;
        unsigned expr_bit;
        u32Value table;
        Instruction::Instruction *offset;
        ValType element_type;
        Elements *elements;

        void clean();

    public:
        ElemSegType();
        void generate(Context *context);
        void getEncode(DataOutputStream *out);
        ~ElemSegType();
    };

    class ElemSection : public Section
    {
    public:
        SectionId id();
        TypeEx *getTypeEx();
    };
}
#endif