#include "data_output_stream.h"
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

DataOutputStream::DataOutputStream(int capacity)
{
    this->capacity = capacity;
    this->pos = 0;
    this->buf = (unsigned char *)malloc(capacity);
    this->delta = 0x200000;
    assert(buf != nullptr);
}

DataOutputStream::~DataOutputStream()
{
    free(buf);
    buf = nullptr;
}

void DataOutputStream::check_capacity(int len)
{
    if (pos + len >= capacity)
    {
        unsigned char *new_buf = (unsigned char *)malloc(capacity + delta + len);
        memcpy(new_buf, buf, pos);
        this->capacity += delta + len;
        free(buf);
        buf = new_buf;
    }
}

void DataOutputStream::write_byte(unsigned char byte)
{
    check_capacity(1);
    buf[pos++] = byte;
}

void DataOutputStream::write_uint(uint32_t x)
{
    check_capacity(sizeof(uint32_t));
    uint32_t *p = (uint32_t *)(buf + pos);
    *p = x;
    pos += sizeof(uint32_t);
}

void DataOutputStream::write_long(long x)
{
    check_capacity(sizeof(long));
    long *p = (long *)(buf + pos);
    *p = x;
    pos += sizeof(long);
}

void DataOutputStream::write_ulong(uint64_t x)
{
    check_capacity(sizeof(uint64_t));
    uint64_t *p = (uint64_t *)(buf + pos);
    *p = x;
    pos += sizeof(uint64_t);
}

void DataOutputStream::write_buf(void *data, size_t len)
{
    check_capacity(len);
    memcpy(buf + pos, data, len);
    pos += len;
}

void DataOutputStream::write_from_data(DataOutputStream *data)
{
    int len = data->pos;
    check_capacity(len);
    memcpy(buf + pos, data->buf, len);
    pos += len;
}

int DataOutputStream::size()
{
    return pos;
}

void DataOutputStream::write_to_file(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0777);
    if (fd < 0)
    {
        printf("[DataOutputStream] open file path error!\n");
        abort();
    }
    write(fd, buf, pos);
    close(fd);
}

const unsigned char *DataOutputStream::buffer()
{
    return buf;
}