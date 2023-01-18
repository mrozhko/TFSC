#ifndef __CA_TEST_H__
#define __CA_TEST_H__
#include <string>


#include "proto/block.pb.h"
#include "proto/transaction.pb.h"

int printRocksdb(uint64_t start, uint64_t end, bool isConsoleOutput, std::ostream & stream);
int printBlock(const CBlock & block, bool isConsoleOutput, std::ostream & stream);
int printTx(const CTransaction & tx, bool isConsoleOutput, std::ostream & stream);
std::string printBlocks(int num = 0, bool pre_hash_flag = false);
#endif
