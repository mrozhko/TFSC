#ifndef __CA_ADVANCEDMENU_H_
#define __CA_ADVANCEDMENU_H_

#include <cstdint>

#include "db/db_api.h"


#pragma region FirstLevelMenu
//rootMenu
void menu_advanced();
#pragma endregion

//caMenu
void menu_ca();
void gen_key();
void in_private_key();
void out_private_key();
void rollback();
void GetStakeList();
int GetBounsAddrInfo();

//netMenu
void menu_net();
void send_message_to_user();
void show_my_k_bucket();
void kick_out_node();
void test_echo();
void print_req_and_ack();

#pragma region ThreeLevelMenu
//blockinfoMenu
void menu_blockinfo();
void get_tx_block_info(uint64_t& top);

//testMenu
void menu_test();
void gen_mnemonic();
void get_balance_by_utxo();
int imitate_create_tx_struct();
void multi_tx();

void get_all_pledge_addr();
void auto_tx();
void get_blockinfo_by_txhash();
void get_the_top_1000_hign_abnormal_signatures();
void Create_multi_thread_automatic_transaction();
void Create_multi_thread_automatic_stake_transaction();
void Auto_investment();
void print_verify_node();


void get_tx_hash_by_height();
void get_investedNodeBlance();
void print_database_block();

//nodeMenu
void print_block_cache();
void printTxdata();
void evmAddrConversion();

void printBenchmarkToFile();

namespace ThreadTest
{
    void TestCreateTx_2(const std::string& from,const std::string& to);
    void test_createTx(uint32_t tranNum, std::vector<std::string> addrs, int sleepTime);
    void set_StopTx_flag(const bool &flag);
    void get_StopTx_flag(bool &flag);
}

#pragma endregion
#endif
