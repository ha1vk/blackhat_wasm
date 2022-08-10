#ifndef RANDOM_H
#define RANDOM_H

#define CHOICE(ARR) (ARR[context->random->selector(sizeof(ARR) / sizeof(ARR[0]))])
#define CHOICE_VEC(vec) (vec[context->random->selector(vec.size())])

#include <cstdint>
#include <stdio.h>

const uint32_t NAN32 = 0b01111111110000000000000000000000;
const uint64_t NAN64 = 0b0111111111111000000000000000000000000000000000000000000000000000;
const uint32_t INF32 = 0b01111111100000000000000000000000;
const uint64_t INF64 = 0b0111111111110000000000000000000000000000000000000000000000000000;

class Random
{
private:
    static int unrandom_fd;
    bool use_lib_fuzzer;
    void *libfuzzer_data;
    size_t pos;
    size_t libfuzzer_len;
    unsigned int rand_from_dev();
    unsigned int rand_from_libfuzzer();

public:
    Random();
    Random(void *data,size_t len);
    static void init_fd();
    static void close_fd();
    unsigned int my_rand();
    bool gbool();
    int selector(int num);
    int range(int low, int high);
    unsigned range_u(unsigned low, unsigned high);
    char byte();
    uint32_t ushort();
    int32_t integer();
    int64_t integer64();
    __int128_t integer128();
    uint32_t float32();
    uint64_t float64();
};

#endif