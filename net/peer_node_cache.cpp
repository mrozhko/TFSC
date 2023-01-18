#include "peer_node_cache.h"


int PeerNodeCache::Add(const Node &_node)
{
    std::lock_guard<std::mutex> lock(_mutex);
    Node selfNode = MagicSingleton<PeerNode>::GetInstance()->get_self_node();
    if(_node.base58address == selfNode.base58address)
    {
        return -1;
    }

    for(auto &iter : _register_pool)
    {
        if(_node.base58address == iter.first)
        {
            return -2;
        }
    }
    _register_pool.insert(std::make_pair(_node.base58address, _node));
    return 0;
}

int PeerNodeCache::Remove(const Node &_node)
{
    std::lock_guard<std::mutex> lock(_mutex);
    for(auto &iter : _register_pool)
    {
        if(_node.base58address == iter.first)
        {
            _register_pool.erase(_node.base58address);
            return 0;
        }
    }
    DEBUGLOG("not found _node.base58address : {}", _node.base58address);
    return -1;
}

std::vector<Node> PeerNodeCache::GetNodeCache()
{
    std::lock_guard<std::mutex> lock(_mutex);
	std::vector<Node> rst;
	auto cb = _register_pool.cbegin(), ce = _register_pool.cend();
	for (; cb != ce; ++cb)
	{
		rst.push_back(cb->second);
	}
	return rst;
}

int PeerNodeCache::PrintToFile()
{
    std::string fileName = "register_node.txt";
    std::ofstream filestream;
    filestream.open(fileName);
    if (!filestream)
    {
        std::cout << "Open file failed!" << std::endl;
        return -1;
    }

    std::vector<Node> nodelist = GetNodeCache();

    std::map<std::string, std::string> nodeInfo;
    std::set<std::string> nodeCache;
    for(auto &i : nodelist)
    {
        nodeCache.insert(i.base58address);
    }

	filestream << "------------------------------------------------------------------------------------------------------------" << std::endl;
	for (auto& i : nodeCache)
	{
        filestream
        	<< "  base58(" << i << ")"
			<< std::endl;
	}
	filestream << "------------------------------------------------------------------------------------------------------------" << std::endl;
	filestream << "PeerNode size is: " << nodeCache.size() << std::endl;
    return 0;
}