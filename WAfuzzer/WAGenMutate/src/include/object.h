#ifndef OBJECT_H
#define OBJECT_H

template <class T>
const T *instanceObj()
{
    T *obj = new T();
    return obj;
}
#endif