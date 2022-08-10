#ifndef CONTEXT_H
#define CONTEXT_H

#include "random.h"
#include <map>
#include <vector>

using std::map;
using std::vector;

class Context
{
private:
    bool dfs_cfg(int v, int u, map<int, map<int, bool> > &path);

public:
    unsigned data_count;
    unsigned code_count;
    unsigned type_count;
    Random *random;
    map<int, vector<int> > cfg_graph; //有向图，记录函数调用时的流程，避免形成递归死循环
    Context();
    Context(Random *random);
    void reset();
    bool check_loop(int v, int u); //检查从点v出发是否会回到v
    void add_cfg(int v, int u);    //添加控制流连接线
    ~Context();
};
#endif