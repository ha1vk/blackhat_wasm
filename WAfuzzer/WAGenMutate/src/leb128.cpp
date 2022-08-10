#include "leb128.h"

int unsigned_to_leb128(uint64_t val, unsigned char *s)
{
    unsigned char c;
    int more;
    int len = 0;
    do
    {
        c = val & 0x7f;
        val >>= 7;
        more = val != 0;
        *s++ = c | (more ? 0x80 : 0);
        len++;
    } while (more);
    return len;
}

void unsigned_to_leb128(uint64_t val, DataOutputStream *s)
{
    unsigned char c;
    int more;
    do
    {
        c = val & 0x7f;
        val >>= 7;
        more = val != 0;
        s->write_byte(c | (more ? 0x80 : 0));
    } while (more);
}

void signed_to_leb128(int64_t val, DataOutputStream *s)
{
    unsigned char c;
    int more;
    do
    {
        c = val & 0x7f;
        val >>= 7;
        more = c & 0x40 ? val != -1 : val != 0;
        s->write_byte(c | (more ? 0x80 : 0));
    } while (more);
}

int signed_to_leb128(int64_t val, unsigned char *s)
{
    unsigned char c;
    int more;
    int len = 0;
    do
    {
        c = val & 0x7f;
        val >>= 7;
        more = c & 0x40 ? val != -1 : val != 0;
        *s++ = c | (more ? 0x80 : 0);
        len++;
    } while (more);
    return len;
}