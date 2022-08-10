#ifndef LEB128_H
#define LEB128_H
#include <stdint.h>
#include "data_output_stream.h"

int signed_to_leb128(int64_t val, unsigned char *s);
void signed_to_leb128(int64_t val, DataOutputStream *s);

int unsigned_to_leb128(uint64_t val, unsigned char *s);
void unsigned_to_leb128(uint64_t val, DataOutputStream *s);

#endif