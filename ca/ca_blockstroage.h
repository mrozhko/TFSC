#ifndef _BLOCK_STROAGE_
#define _BLOCK_STROAGE_

#include "ca/ca_transtroage.h"
#include "ca/ca_blockmonitor.h"
#include "utils/MagicSingleton.h"
#include "utils/VRF.hpp"





class BlockStroage
{
public:
    BlockStroage(){ StartTimer(); };
    ~BlockStroage() = default;
    BlockStroage(BlockStroage &&) = delete;
    BlockStroage(const BlockStroage &) = delete;
    BlockStroage &operator=(BlockStroage&&) = delete;
    BlockStroage &operator=(const BlockStroage &) = delete;

public:
	int AddBlock(const BlockMsg &msg);
	int UpdateBlock(const BlockMsg &msg);

private:

	void StartTimer();
	void BlockCheck();
	void composeEndBlockmsg(std::vector<BlockMsg> &msgvec);
	void Remove(const uint64_t &time);

private:

	CTimer _block_timer;
	std::mutex _block_mutex_;
	std::map<uint64_t, std::vector<BlockMsg>> _BlockMap;

};



#endif