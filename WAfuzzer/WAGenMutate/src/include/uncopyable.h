#ifndef HM_UNCOPYABLE_H
#define HM_UNCOPYABLE_H
class uncopyable
{
protected:
    uncopyable() {}
    ~uncopyable() {}

private:
    uncopyable(const uncopyable &);
    uncopyable &operator=(const uncopyable &);
};
#endif