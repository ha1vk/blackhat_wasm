#ifndef HM_SERIALIZE_STREAM_H
#define HM_SERIALIZE_STREAM_H

#include <string>
using std::string;
#include "uncopyable.h"

class DataOutputStream : public uncopyable
{
private:
    //容量
    int capacity;
    //当前位置
    int pos;
    //数据区
    unsigned char *buf;
    int delta;

public:
    DataOutputStream(int capacity = 0x200000);
    ~DataOutputStream();
    void check_capacity(int len);
    void write_byte(unsigned char byte);
    void write_int(int x);
    void write_uint(uint32_t x);
    void write_long(long x);
    void write_ulong(uint64_t x);
    void write_buf(void *data, size_t len);
    void write_from_data(DataOutputStream *data);
    const unsigned char *buffer();
    int size();
    void write_to_file(const char *path);
};

#endif