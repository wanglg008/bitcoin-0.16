// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include <string>

class CScheduler;
class CWallet;

namespace boost
{
class thread_group;
} // namespace boost

void StartShutdown();
bool ShutdownRequested();
/** Interrupt threads */
void Interrupt();
void Shutdown();
//!Initialize the logging infrastructure
void InitLogging();
//!Parameter interaction: change current parameters depending on various rules
void InitParameterInteraction();

/** Initialize bitcoin core: Basic context setup.                                               初始化比特币的核心:基本的环境设置。
 *  @note This can be done before daemonization. Do not call Shutdown() if this function fails. @note：这可以在daemonization之前完成。如果此函数失败，请不要调用Shutdown()函数。
 *  @pre Parameters should be parsed and config file should be read.                            @pre：对参数进行解析，并读取配置文件。
 */
bool AppInitBasicSetup();
/**
 * Initialization: parameter interaction.                                                       初始化：参数的交互。
 * @note This can be done before daemonization. Do not call Shutdown() if this function fails.  @note：这可以在daemonization之前完成。如果此函数失败，请不要调用Shutdown()。
 * @pre Parameters should be parsed and config file should be read, AppInitBasicSetup should have been called. @pre：参数应该被解析，并且应该读取配置文件，而且AppInitBasicSetup()函数应该已经被调用。
 */
bool AppInitParameterInteraction();
/**
 * Initialization sanity checks: ecc init, sanity checks, dir lock.                                                     初始化健全性检查：ecc初始化、健全性检查、目录锁检查。
 * @note This can be done before daemonization. Do not call Shutdown() if this function fails.                          注意：这可以在daemonization之前完成。如果此函数失败，请不要调用Shutdown()。
 * @pre Parameters should be parsed and config file should be read, AppInitParameterInteraction should have been called.前提：参数解析和配置文件应该已经被读过，AppInitParameterInteraction()函数应该已经被调用过。
 *///
bool AppInitSanityChecks();
/**
 * Lock bitcoin core data directory.                                                                                     锁定比特币核心数据目录。
 * @note This should only be done after daemonization. Do not call Shutdown() if this function fails.                    注意： 这只能在守护进程之后完成。 如果此功能失败，请勿调用Shutdown（）。
 * @pre Parameters should be parsed and config file should be read, AppInitSanityChecks should have been called.         前提： 应该解析参数并读取配置文件，应该调用过AppInitSanityChecks。
 */
bool AppInitLockDataDirectory();
/**
 * Bitcoin core main initialization.                                                                                     比特币核心的主要初始化。
 * @note This should only be done after daemonization. Call Shutdown() if this function fails.                           注意： 这只能在守护进程之后完成。 如果这个函数失败，调用Shutdown（）。
 * @pre Parameters should be parsed and config file should be read, AppInitLockDataDirectory should have been called.    前提： 应该解析参数并读取配置文件，应该调用AppInitLockDataDirectory。
 */
bool AppInitMain();

/** The help message mode determines what help message to show */
enum HelpMessageMode {
    HMM_BITCOIND,   //比特币后台进程帮助信息
    HMM_BITCOIN_QT  //比特币前端界面程序帮助信息
};

/** Help for options shared between UI and daemon (for -help) */
std::string HelpMessage(HelpMessageMode mode);
/** Returns licensing information (for -version) */
std::string LicenseInfo();

#endif // BITCOIN_INIT_H
