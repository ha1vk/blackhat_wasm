#include "context.h"

Context::Context()
{
    reset();
    random = new Random();
}

Context::Context(Random *random)
{
    reset();
    this->random = random;
}

void Context::reset()
{
    data_count = -1;
    code_count = -1;
    type_count = -1;
}

bool Context::dfs_cfg(int v, int u, map<int, map<int, bool> > &path)
{
    if (v == u)
    {
        return true;
    }
    if (cfg_graph.find(v) == cfg_graph.end())
    {
        return false;
    }
    vector<int> &neighbors = cfg_graph[v];
    int size = neighbors.size();
    bool ans = false;
    for (int i = 0; i < size; i++)
    {
        int n = neighbors[i];
        if (!path[v][n])
        {
            path[v][n] = 1;
            ans = dfs_cfg(n, u, path);
            if (ans)
            {
                break;
            }
        }
    }
    return ans;
}

bool Context::check_loop(int v, int u)
{
    map<int, map<int, bool> > path;
    return dfs_cfg(u, v, path);
}

void Context::add_cfg(int v, int u)
{
    cfg_graph[v].push_back(u);
}

Context::~Context()
{
    if (random)
    {
        delete random;
    }
}