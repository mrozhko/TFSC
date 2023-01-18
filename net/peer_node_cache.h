#ifndef _PEER_NODE_CACHE_H
#define _PEER_NODE_CACHE_H

#include <map>
#include <set>
#include <mutex>
#include <vector>
#include <iostream>
#include <fstream>
#include "node.hpp"
#include "../include/logging.h"
#include "../utils/MagicSingleton.h"
#include "../net/peer_node.h"

class PeerNodeCache
{
public:
    PeerNodeCache()=default;
    ~PeerNodeCache()=default;
    int Add(const Node &_node);
    int Remove(const Node &_node);
    int PrintToFile();
    std::vector<Node> GetNodeCache();                                                    
private:
    std::mutex _mutex;
    std::map<std::string, Node> _register_pool;

};

#endif