#include "random.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int Random::unrandom_fd = -1;

void Random::init_fd()
{
    if (unrandom_fd == -1)
    {
        unrandom_fd = open("/dev/urandom", O_RDONLY);
        if (unrandom_fd == -1)
        {
            puts("Random::init() Error!");
            abort();
        }
        atexit(close_fd);
    }
}

Random::Random()
{
    use_lib_fuzzer = false;
    libfuzzer_data = NULL;
    libfuzzer_len = 0;
    pos = 0;
}

Random::Random(void *data, size_t len)
{
    use_lib_fuzzer = true;
    libfuzzer_data = data;
    libfuzzer_len = len;
    pos = 0;
}

void Random::close_fd()
{
    close(unrandom_fd);
}

unsigned int Random::rand_from_dev()
{
    unsigned int x = 0;
    if (read(unrandom_fd, &x, sizeof(unsigned int)) != 4)
    {
        puts("Random::my_rand() Error!");
        abort();
    }
    return x;
}

unsigned int Random::rand_from_libfuzzer()
{
    unsigned int x = 0;
    if (pos + 4 <= libfuzzer_len)
    {
        x = *(unsigned *)((char *)libfuzzer_data + pos);
        pos += 4;
    }
    else //不够用，直接返回0
    {
        x = 0;
    }
    return x;
}

unsigned int Random::my_rand()
{
    if (use_lib_fuzzer)
    {
        return rand_from_libfuzzer();
    }
    else
    {
        return rand_from_dev();
    }
}

int Random::range(int low, int high)
{
    return (my_rand() % (high - low + 1)) + low;
}

unsigned Random::range_u(unsigned low, unsigned high)
{
    return (my_rand() % (high - low + 1)) + low;
}

char Random::byte()
{
    return range(0, 255);
}
bool Random::gbool()
{
    return range(0, 1);
}

int Random::selector(int num)
{
    assert(num != 0);
    return range(0, num - 1);
}

uint32_t Random::ushort()
{
    int c = selector(7);
    uint32_t v = 0;
    switch (c)
    {
    case 0:
    case 1:
        v = 0;
        break;
    case 2:
        v = 1;
        break;
    case 3:
        v = range(0, 16);
        break;
    case 4:
        v = range(0, 100);
        break;
    case 5:
        v = range(0, 1000);
        break;
    default: //一些临界值
        int c2 = selector(4);
        switch (c2)
        {
        case 0:
            v = 0x10000;
            break;
        case 1:
            v = 0xffff;
            break;
        case 2:
            v = 0x8000;
            break;
        default:
            v = range(0, 65536);
            break;
        }
    }
    return v;
}

int32_t Random::integer()
{
    bool sign = gbool();
    int c = selector(7);
    int32_t v = 0;
    switch (c)
    {
    case 0:
    case 1:
        v = 0;
        break;
    case 2:
        v = 1;
        break;
    case 3:
        v = range(0, 16);
        break;
    case 4:
        v = range(0, 100);
        break;
    case 5:
        v = range(0, 1000);
        break;
    default: //一些临界值
        int c2 = selector(7);
        switch (c2)
        {
        case 0:
            v = 0x10000;
            break;
        case 1:
            v = 0x10001;
            break;
        case 2:
            v = 0xffff;
            break;
        case 3:
            v = 0x8000;
            break;
        case 4:
            v = 0xffffffff;
            break;
        case 5:
            v = 0x80000000;
            break;
        default:
            v = range(0, 50000);
            break;
        }
    }
    if (sign)
    {
        return -v;
    }
    return v;
}

int64_t Random::integer64()
{
    bool sign = gbool();
    int c = selector(7);
    int64_t v = 0;
    switch (c)
    {
    case 0:
    case 1:
        v = 0;
        break;
    case 2:
        v = 1;
        break;
    case 3:
        v = range(0, 16);
        break;
    case 4:
        v = range(0, 100);
        break;
    case 5:
        v = range(0, 1000);
        break;
    default: //一些临界值
        int c2 = selector(7);
        switch (c2)
        {
        case 0:
            v = 0x100000000;
            break;
        case 1:
            v = 0x100000001;
            break;
        case 2:
            v = 0xffffffff;
            break;
        case 3:
            v = 0x80000000;
            break;
        case 4:
            v = 0xffffffffffffffff;
            break;
        case 5:
            v = 0x8000000000000000;
            break;
        default:
            v = range(0, 50000);
            break;
        }
    }
    if (sign)
    {
        v = -v;
    }
    return v;
}

__int128_t Random::integer128()
{
    bool sign = gbool();
    int c = selector(7);
    __int128_t v = 0;
    unsigned char *p = (unsigned char *)&v;
    switch (c)
    {
    case 0:
    case 1:
        v = 0;
        break;
    case 2:
        v = 1;
        break;
    case 3:
        v = range(0, 16);
        break;
    case 4:
        v = range(0, 100);
        break;
    case 5:
        v = range(0, 1000);
        break;
    default: //一些临界值
        int c2 = selector(7);
        switch (c2)
        {
        case 0:
            memset(p, 0, 0x10);
            p[0x8] = 0x1; // v = 0x10000000000000000
            break;
        case 1:
            memset(p, 0, 0x10);
            p[0] = 0x1;
            p[0x8] = 0x1; // v = 0x10000000000000001
            break;
        case 2:
            v = 0xffffffffffffffff;
            break;
        case 3:
            v = 0x8000000000000000;
            break;
        case 4:
            memset(p, 0xff, 0x10); // v = 0xffffffffffffffffffffffffffffffff
            break;
        case 5:
            memset(p, 0, 0x10);
            p[0xf] = 0x8; // v = 0x80000000000000000000000000000000
            break;
        default:
            v = range(0, 50000);
            break;
        }
    }
    if (sign)
    {
        v = -v;
    }
    return v;
}

uint32_t Random::float32()
{
    bool sign = gbool();
    int c = selector(6);
    uint32_t x;
    float ans = 0;
    switch (c)
    {
    case 0:
        ans = gbool();
        break;
    case 1:
    case 2:
        ans = (float)(my_rand() % 666) / 666;
        break;
    default:
        break;
    }
    if (sign)
    {
        ans = -ans;
    }
    if (c < 3)
    {
        x = *(uint32_t *)&ans;
        return x;
    }
    else if (c == 3)
    {
        return NAN32;
    }
    else if (c == 4)
    {
        return INF32;
    }
    else if (c == 5)
    {
        return 0xffffffff;
    }
    return 0;
}

uint64_t Random::float64()
{
    bool sign = gbool();
    int c = selector(6);
    uint64_t x;
    double ans;
    switch (c)
    {
    case 0:
        ans = gbool();
        break;
    case 1:
    case 2:
        ans = (double)(my_rand() % 666) / 666;
        break;
    }
    if (sign)
    {
        ans = -ans;
    }

    if (c < 3)
    {
        x = *(uint64_t *)&ans;
        return x;
    }
    else if (c == 3)
    {
        return NAN64;
    }
    else if (c == 4)
    {
        return INF64;
    }
    else if (c == 5)
    {
        return 0xffffffffffffffff;
    }
    return 0;
}