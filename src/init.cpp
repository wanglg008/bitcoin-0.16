// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <init.h>

#include <addrman.h>
#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <checkpoints.h>
#include <compat/sanity.h>
#include <consensus/validation.h>
#include <fs.h>
#include <httpserver.h>
#include <httprpc.h>
#include <key.h>
#include <validation.h>
#include <miner.h>
#include <netbase.h>
#include <net.h>
#include <net_processing.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <rpc/server.h>
#include <rpc/register.h>
#include <rpc/safemode.h>
#include <rpc/blockchain.h>
#include <script/standard.h>
#include <script/sigcache.h>
#include <scheduler.h>
#include <timedata.h>
#include <txdb.h>
#include <txmempool.h>
#include <torcontrol.h>
#include <ui_interface.h>
#include <util.h>
#include <utilmoneystr.h>
#include <validationinterface.h>
#ifdef ENABLE_WALLET
#include <wallet/init.h>
#endif
#include <warnings.h>
#include <stdint.h>
#include <stdio.h>
#include <memory>

#ifndef WIN32
#include <signal.h>
#endif

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/bind.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>

#if ENABLE_ZMQ
#include <zmq/zmqnotificationinterface.h>
#endif

bool fFeeEstimatesInitialized = false;
static const bool DEFAULT_PROXYRANDOMIZE = true;
static const bool DEFAULT_REST_ENABLE = false;
static const bool DEFAULT_STOPAFTERBLOCKIMPORT = false;

std::unique_ptr<CConnman> g_connman;
std::unique_ptr<PeerLogicValidation> peerLogic;

#if ENABLE_ZMQ
static CZMQNotificationInterface* pzmqNotificationInterface = nullptr;
#endif

#ifdef WIN32
// Win32 LevelDB doesn't use filedescriptors, and the ones used for
// accessing block files don't count towards the fd_set size limit
// anyway.
#define MIN_CORE_FILEDESCRIPTORS 0
#else
#define MIN_CORE_FILEDESCRIPTORS 150
#endif

static const char* FEE_ESTIMATES_FILENAME="fee_estimates.dat";

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

//
// Thread management and startup/shutdown:
//
// The network-processing threads are all part of a thread group
// created by AppInit() or the Qt main() function.
//
// A clean exit happens when StartShutdown() or the SIGTERM
// signal handler sets fRequestShutdown, which makes main thread's
// WaitForShutdown() interrupts the thread group.
// And then, WaitForShutdown() makes all other on-going threads
// in the thread group join the main thread.
// Shutdown() is then called to clean up database connections, and stop other
// threads that should only be stopped after the main network-processing
// threads have exited.
//
// Shutdown for Qt is very similar, only it uses a QTimer to detect
// fRequestShutdown getting set, and then does the normal Qt
// shutdown thing.
//

std::atomic<bool> fRequestShutdown(false);
std::atomic<bool> fDumpMempoolLater(false);

void StartShutdown()
{
    fRequestShutdown = true;
}
bool ShutdownRequested()
{
    return fRequestShutdown;
}

/**
 * This is a minimally invasive approach to shutdown on LevelDB read errors from the
 * chainstate, while keeping user interface out of the common library, which is shared
 * between bitcoind, and bitcoin-qt and non-server tools.
*/
class CCoinsViewErrorCatcher final : public CCoinsViewBacked
{
public:
    explicit CCoinsViewErrorCatcher(CCoinsView* view) : CCoinsViewBacked(view) {}
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override {
        try {
            return CCoinsViewBacked::GetCoin(outpoint, coin);
        } catch(const std::runtime_error& e) {
            uiInterface.ThreadSafeMessageBox(_("Error reading from database, shutting down."), "", CClientUIInterface::MSG_ERROR);
            LogPrintf("Error reading from database: %s\n", e.what());
            // Starting the shutdown sequence and returning false to the caller would be
            // interpreted as 'entry not found' (as opposed to unable to read data), and
            // could lead to invalid interpretation. Just exit immediately, as we can't
            // continue anyway, and all writes should be atomic.
            abort();
        }
    }
    // Writes do not need similar protection, as failure to write is handled by the caller.
};

static std::unique_ptr<CCoinsViewErrorCatcher> pcoinscatcher;
static std::unique_ptr<ECCVerifyHandle> globalVerifyHandle;

static boost::thread_group threadGroup;
static CScheduler scheduler;

void Interrupt()
{
    InterruptHTTPServer();
    InterruptHTTPRPC();
    InterruptRPC();
    InterruptREST();
    InterruptTorControl();
    if (g_connman)
        g_connman->Interrupt();
}

void Shutdown()
{
    LogPrintf("%s: In progress...\n", __func__);
    static CCriticalSection cs_Shutdown;
    TRY_LOCK(cs_Shutdown, lockShutdown);
    if (!lockShutdown)
        return;

    /// Note: Shutdown() must be able to handle cases in which initialization failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    RenameThread("bitcoin-shutoff");
    mempool.AddTransactionsUpdated(1);

    StopHTTPRPC();
    StopREST();
    StopRPC();
    StopHTTPServer();
#ifdef ENABLE_WALLET
    FlushWallets();
#endif
    MapPort(false);

    // Because these depend on each-other, we make sure that neither can be
    // using the other before destroying them.
    if (peerLogic) UnregisterValidationInterface(peerLogic.get());
    if (g_connman) g_connman->Stop();
    peerLogic.reset();
    g_connman.reset();

    StopTorControl();

    // After everything has been shut down, but before things get flushed, stop the
    // CScheduler/checkqueue threadGroup
    threadGroup.interrupt_all();
    threadGroup.join_all();

    if (fDumpMempoolLater && gArgs.GetArg("-persistmempool", DEFAULT_PERSIST_MEMPOOL)) {
        DumpMempool();
    }

    if (fFeeEstimatesInitialized)
    {
        ::feeEstimator.FlushUnconfirmed(::mempool);
        fs::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
        CAutoFile est_fileout(fsbridge::fopen(est_path, "wb"), SER_DISK, CLIENT_VERSION);
        if (!est_fileout.IsNull())
            ::feeEstimator.Write(est_fileout);
        else
            LogPrintf("%s: Failed to write fee estimates to %s\n", __func__, est_path.string());
        fFeeEstimatesInitialized = false;
    }

    // FlushStateToDisk generates a SetBestChain callback, which we should avoid missing
    if (pcoinsTip != nullptr) {
        FlushStateToDisk();
    }

    // After there are no more peers/RPC left to give us new data which may generate
    // CValidationInterface callbacks, flush them...
    GetMainSignals().FlushBackgroundCallbacks();

    // Any future callbacks will be dropped. This should absolutely be safe - if
    // missing a callback results in an unrecoverable situation, unclean shutdown
    // would too. The only reason to do the above flushes is to let the wallet catch
    // up with our current chain to avoid any strange pruning edge cases and make
    // next startup faster by avoiding rescan.

    {
        LOCK(cs_main);
        if (pcoinsTip != nullptr) {
            FlushStateToDisk();
        }
        pcoinsTip.reset();
        pcoinscatcher.reset();
        pcoinsdbview.reset();
        pblocktree.reset();
    }
#ifdef ENABLE_WALLET
    StopWallets();
#endif

#if ENABLE_ZMQ
    if (pzmqNotificationInterface) {
        UnregisterValidationInterface(pzmqNotificationInterface);
        delete pzmqNotificationInterface;
        pzmqNotificationInterface = nullptr;
    }
#endif

#ifndef WIN32
    try {
        fs::remove(GetPidFile());
    } catch (const fs::filesystem_error& e) {
        LogPrintf("%s: Unable to remove pidfile: %s\n", __func__, e.what());
    }
#endif
    UnregisterAllValidationInterfaces();
    GetMainSignals().UnregisterBackgroundSignalScheduler();
    GetMainSignals().UnregisterWithMempoolSignals(mempool);
#ifdef ENABLE_WALLET
    CloseWallets();
#endif
    globalVerifyHandle.reset();
    ECC_Stop();
    LogPrintf("%s: done\n", __func__);
}

/**
 * Signal handlers are very limited in what they are allowed to do.
 * The execution context the handler is invoked in is not guaranteed,
 * so we restrict handler operations to just touching variables:
 *///该函数就是简单的把全局变量fRequestShutdown设置成true，所有正在运行的线程将根据一定的规则停止运行。
static void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}
//该函数就是把全局变量fReopenDebugLog设置成true。而此变量设置成true后就会使util.cpp中的LogPrintStr()将重新打开调试日志打印文件
static void HandleSIGHUP(int)
{
    fReopenDebugLog = true;
}
//函数对信号对象的句柄、标志和掩码赋值，并将该信号对象传递给中断信号处理函数。
#ifndef WIN32
static void registerSignalHandler(int signal, void(*handler)(int))
{
    struct sigaction sa;        //信号处理对象
    sa.sa_handler = handler;    //进程终止信号处理句柄
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signal, &sa, nullptr);//中断信号处理
}
#endif

void OnRPCStarted()
{
    uiInterface.NotifyBlockTip.connect(&RPCNotifyBlockChange);
}

void OnRPCStopped()
{
    uiInterface.NotifyBlockTip.disconnect(&RPCNotifyBlockChange);
    RPCNotifyBlockChange(false, nullptr);
    cvBlockChange.notify_all();
    LogPrint(BCLog::RPC, "RPC stopped.\n");
}
//帮助UI和守护进程共享选项(用于-help)
std::string HelpMessage(HelpMessageMode mode)
{
    const auto defaultBaseParams = CreateBaseChainParams(CBaseChainParams::MAIN);
    const auto testnetBaseParams = CreateBaseChainParams(CBaseChainParams::TESTNET);
    const auto defaultChainParams = CreateChainParams(CBaseChainParams::MAIN);
    const auto testnetChainParams = CreateChainParams(CBaseChainParams::TESTNET);
    const bool showDebug = gArgs.GetBoolArg("-help-debug", false);

    // When adding new options to the categories, please keep and ensure alphabetical ordering.
    // Do not translate _(...) -help-debug options, Many technical terms, and only a very small audience, so is unnecessary stress to translators.
    std::string strUsage = HelpMessageGroup(_("Options:"));
    strUsage += HelpMessageOpt("-?", _("Print this help message and exit"));
    strUsage += HelpMessageOpt("-version", _("Print version and exit"));
    strUsage += HelpMessageOpt("-alertnotify=<cmd>", _("Execute command when a relevant alert is received or we see a really long fork (%s in cmd is replaced by message)"));
    strUsage += HelpMessageOpt("-blocknotify=<cmd>", _("Execute command when the best block changes (%s in cmd is replaced by block hash)"));
    if (showDebug)
        strUsage += HelpMessageOpt("-blocksonly", strprintf(_("Whether to operate in a blocks only mode (default: %u)"), DEFAULT_BLOCKSONLY));
    strUsage +=HelpMessageOpt("-assumevalid=<hex>", strprintf(_("If this block is in the chain assume that it and its ancestors are valid and potentially skip their script verification (0 to verify all, default: %s, testnet: %s)"), defaultChainParams->GetConsensus().defaultAssumeValid.GetHex(), testnetChainParams->GetConsensus().defaultAssumeValid.GetHex()));
    strUsage += HelpMessageOpt("-conf=<file>", strprintf(_("Specify configuration file (default: %s)"), BITCOIN_CONF_FILENAME));
    if (mode == HMM_BITCOIND)
    {
#if HAVE_DECL_DAEMON
        strUsage += HelpMessageOpt("-daemon", _("Run in the background as a daemon and accept commands"));
#endif
    }
    strUsage += HelpMessageOpt("-datadir=<dir>", _("Specify data directory"));
    if (showDebug) {
        strUsage += HelpMessageOpt("-dbbatchsize", strprintf("Maximum database write batch size in bytes (default: %u)", nDefaultDbBatchSize));
    }
    strUsage += HelpMessageOpt("-dbcache=<n>", strprintf(_("Set database cache size in megabytes (%d to %d, default: %d)"), nMinDbCache, nMaxDbCache, nDefaultDbCache));
    if (showDebug)
        strUsage += HelpMessageOpt("-feefilter", strprintf("Tell other nodes to filter invs to us by our mempool min fee (default: %u)", DEFAULT_FEEFILTER));
    strUsage += HelpMessageOpt("-loadblock=<file>", _("Imports blocks from external blk000??.dat file on startup"));
    strUsage += HelpMessageOpt("-debuglogfile=<file>", strprintf(_("Specify location of debug log file: this can be an absolute path or a path relative to the data directory (default: %s)"), DEFAULT_DEBUGLOGFILE));
    strUsage += HelpMessageOpt("-maxorphantx=<n>", strprintf(_("Keep at most <n> unconnectable transactions in memory (default: %u)"), DEFAULT_MAX_ORPHAN_TRANSACTIONS));
    strUsage += HelpMessageOpt("-maxmempool=<n>", strprintf(_("Keep the transaction memory pool below <n> megabytes (default: %u)"), DEFAULT_MAX_MEMPOOL_SIZE));
    strUsage += HelpMessageOpt("-mempoolexpiry=<n>", strprintf(_("Do not keep transactions in the mempool longer than <n> hours (default: %u)"), DEFAULT_MEMPOOL_EXPIRY));
    if (showDebug) {
        strUsage += HelpMessageOpt("-minimumchainwork=<hex>", strprintf("Minimum work assumed to exist on a valid chain in hex (default: %s, testnet: %s)", defaultChainParams->GetConsensus().nMinimumChainWork.GetHex(), testnetChainParams->GetConsensus().nMinimumChainWork.GetHex()));
    }
    strUsage += HelpMessageOpt("-persistmempool", strprintf(_("Whether to save the mempool on shutdown and load on restart (default: %u)"), DEFAULT_PERSIST_MEMPOOL));
    strUsage += HelpMessageOpt("-blockreconstructionextratxn=<n>", strprintf(_("Extra transactions to keep in memory for compact block reconstructions (default: %u)"), DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN));
    strUsage += HelpMessageOpt("-par=<n>", strprintf(_("Set the number of script verification threads (%u to %d, 0 = auto, <0 = leave that many cores free, default: %d)"),
        -GetNumCores(), MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS));
#ifndef WIN32
    strUsage += HelpMessageOpt("-pid=<file>", strprintf(_("Specify pid file (default: %s)"), BITCOIN_PID_FILENAME));
#endif
    strUsage += HelpMessageOpt("-prune=<n>", strprintf(_("Reduce storage requirements by enabling pruning (deleting) of old blocks. This allows the pruneblockchain RPC to be called to delete specific blocks, and enables automatic pruning of old blocks if a target size in MiB is provided. This mode is incompatible with -txindex and -rescan. "
            "Warning: Reverting this setting requires re-downloading the entire blockchain. "
            "(default: 0 = disable pruning blocks, 1 = allow manual pruning via RPC, >%u = automatically prune block files to stay under the specified target size in MiB)"), MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
    strUsage += HelpMessageOpt("-reindex-chainstate", _("Rebuild chain state from the currently indexed blocks"));
    strUsage += HelpMessageOpt("-reindex", _("Rebuild chain state and block index from the blk*.dat files on disk"));
#ifndef WIN32
    strUsage += HelpMessageOpt("-sysperms", _("Create new files with system default permissions, instead of umask 077 (only effective with disabled wallet functionality)"));
#endif
    strUsage += HelpMessageOpt("-txindex", strprintf(_("Maintain a full transaction index, used by the getrawtransaction rpc call (default: %u)"), DEFAULT_TXINDEX));

    strUsage += HelpMessageGroup(_("Connection options:"));
    strUsage += HelpMessageOpt("-addnode=<ip>", _("Add a node to connect to and attempt to keep the connection open (see the `addnode` RPC command help for more info)"));
    strUsage += HelpMessageOpt("-banscore=<n>", strprintf(_("Threshold for disconnecting misbehaving peers (default: %u)"), DEFAULT_BANSCORE_THRESHOLD));
    strUsage += HelpMessageOpt("-bantime=<n>", strprintf(_("Number of seconds to keep misbehaving peers from reconnecting (default: %u)"), DEFAULT_MISBEHAVING_BANTIME));
    strUsage += HelpMessageOpt("-bind=<addr>", _("Bind to given address and always listen on it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-connect=<ip>", _("Connect only to the specified node(s); -connect=0 disables automatic connections (the rules for this peer are the same as for -addnode)"));
    strUsage += HelpMessageOpt("-discover", _("Discover own IP addresses (default: 1 when listening and no -externalip or -proxy)"));
    strUsage += HelpMessageOpt("-dns", _("Allow DNS lookups for -addnode, -seednode and -connect") + " " + strprintf(_("(default: %u)"), DEFAULT_NAME_LOOKUP));
    strUsage += HelpMessageOpt("-dnsseed", _("Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -connect used)"));
    strUsage += HelpMessageOpt("-externalip=<ip>", _("Specify your own public address"));
    strUsage += HelpMessageOpt("-forcednsseed", strprintf(_("Always query for peer addresses via DNS lookup (default: %u)"), DEFAULT_FORCEDNSSEED));
    strUsage += HelpMessageOpt("-listen", _("Accept connections from outside (default: 1 if no -proxy or -connect)"));
    strUsage += HelpMessageOpt("-listenonion", strprintf(_("Automatically create Tor hidden service (default: %d)"), DEFAULT_LISTEN_ONION));
    strUsage += HelpMessageOpt("-maxconnections=<n>", strprintf(_("Maintain at most <n> connections to peers (default: %u)"), DEFAULT_MAX_PEER_CONNECTIONS));
    strUsage += HelpMessageOpt("-maxreceivebuffer=<n>", strprintf(_("Maximum per-connection receive buffer, <n>*1000 bytes (default: %u)"), DEFAULT_MAXRECEIVEBUFFER));
    strUsage += HelpMessageOpt("-maxsendbuffer=<n>", strprintf(_("Maximum per-connection send buffer, <n>*1000 bytes (default: %u)"), DEFAULT_MAXSENDBUFFER));
    strUsage += HelpMessageOpt("-maxtimeadjustment", strprintf(_("Maximum allowed median peer time offset adjustment. Local perspective of time may be influenced by peers forward or backward by this amount. (default: %u seconds)"), DEFAULT_MAX_TIME_ADJUSTMENT));
    strUsage += HelpMessageOpt("-onion=<ip:port>", strprintf(_("Use separate SOCKS5 proxy to reach peers via Tor hidden services (default: %s)"), "-proxy"));
    strUsage += HelpMessageOpt("-onlynet=<net>", _("Only connect to nodes in network <net> (ipv4, ipv6 or onion)"));
    strUsage += HelpMessageOpt("-permitbaremultisig", strprintf(_("Relay non-P2SH multisig (default: %u)"), DEFAULT_PERMIT_BAREMULTISIG));
    strUsage += HelpMessageOpt("-peerbloomfilters", strprintf(_("Support filtering of blocks and transaction with bloom filters (default: %u)"), DEFAULT_PEERBLOOMFILTERS));
    strUsage += HelpMessageOpt("-port=<port>", strprintf(_("Listen for connections on <port> (default: %u or testnet: %u)"), defaultChainParams->GetDefaultPort(), testnetChainParams->GetDefaultPort()));
    strUsage += HelpMessageOpt("-proxy=<ip:port>", _("Connect through SOCKS5 proxy"));
    strUsage += HelpMessageOpt("-proxyrandomize", strprintf(_("Randomize credentials for every proxy connection. This enables Tor stream isolation (default: %u)"), DEFAULT_PROXYRANDOMIZE));
    strUsage += HelpMessageOpt("-seednode=<ip>", _("Connect to a node to retrieve peer addresses, and disconnect"));
    strUsage += HelpMessageOpt("-timeout=<n>", strprintf(_("Specify connection timeout in milliseconds (minimum: 1, default: %d)"), DEFAULT_CONNECT_TIMEOUT));
    strUsage += HelpMessageOpt("-torcontrol=<ip>:<port>", strprintf(_("Tor control port to use if onion listening enabled (default: %s)"), DEFAULT_TOR_CONTROL));
    strUsage += HelpMessageOpt("-torpassword=<pass>", _("Tor control port password (default: empty)"));
#ifdef USE_UPNP
#if USE_UPNP
    strUsage += HelpMessageOpt("-upnp", _("Use UPnP to map the listening port (default: 1 when listening and no -proxy)"));
#else
    strUsage += HelpMessageOpt("-upnp", strprintf(_("Use UPnP to map the listening port (default: %u)"), 0));
#endif
#endif
    strUsage += HelpMessageOpt("-whitebind=<addr>", _("Bind to given address and whitelist peers connecting to it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-whitelist=<IP address or network>", _("Whitelist peers connecting from the given IP address (e.g. 1.2.3.4) or CIDR notated network (e.g. 1.2.3.0/24). Can be specified multiple times.") +
        " " + _("Whitelisted peers cannot be DoS banned and their transactions are always relayed, even if they are already in the mempool, useful e.g. for a gateway"));
    strUsage += HelpMessageOpt("-maxuploadtarget=<n>", strprintf(_("Tries to keep outbound traffic under the given target (in MiB per 24h), 0 = no limit (default: %d)"), DEFAULT_MAX_UPLOAD_TARGET));

#ifdef ENABLE_WALLET
    strUsage += GetWalletHelpString(showDebug);
#endif

#if ENABLE_ZMQ
    strUsage += HelpMessageGroup(_("ZeroMQ notification options:"));
    strUsage += HelpMessageOpt("-zmqpubhashblock=<address>", _("Enable publish hash block in <address>"));
    strUsage += HelpMessageOpt("-zmqpubhashtx=<address>", _("Enable publish hash transaction in <address>"));
    strUsage += HelpMessageOpt("-zmqpubrawblock=<address>", _("Enable publish raw block in <address>"));
    strUsage += HelpMessageOpt("-zmqpubrawtx=<address>", _("Enable publish raw transaction in <address>"));
#endif

    strUsage += HelpMessageGroup(_("Debugging/Testing options:"));
    strUsage += HelpMessageOpt("-uacomment=<cmt>", _("Append comment to the user agent string"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-checkblocks=<n>", strprintf(_("How many blocks to check at startup (default: %u, 0 = all)"), DEFAULT_CHECKBLOCKS));
        strUsage += HelpMessageOpt("-checklevel=<n>", strprintf(_("How thorough the block verification of -checkblocks is (0-4, default: %u)"), DEFAULT_CHECKLEVEL));
        strUsage += HelpMessageOpt("-checkblockindex", strprintf("Do a full consistency check for mapBlockIndex, setBlockIndexCandidates, chainActive and mapBlocksUnlinked occasionally. Also sets -checkmempool (default: %u)", defaultChainParams->DefaultConsistencyChecks()));
        strUsage += HelpMessageOpt("-checkmempool=<n>", strprintf("Run checks every <n> transactions (default: %u)", defaultChainParams->DefaultConsistencyChecks()));
        strUsage += HelpMessageOpt("-checkpoints", strprintf("Disable expensive verification for known chain history (default: %u)", DEFAULT_CHECKPOINTS_ENABLED));
        strUsage += HelpMessageOpt("-disablesafemode", strprintf("Disable safemode, override a real safe mode event (default: %u)", DEFAULT_DISABLE_SAFEMODE));
        strUsage += HelpMessageOpt("-deprecatedrpc=<method>", "Allows deprecated RPC method(s) to be used");
        strUsage += HelpMessageOpt("-testsafemode", strprintf("Force safe mode (default: %u)", DEFAULT_TESTSAFEMODE));
        strUsage += HelpMessageOpt("-dropmessagestest=<n>", "Randomly drop 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-fuzzmessagestest=<n>", "Randomly fuzz 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-stopafterblockimport", strprintf("Stop running after importing blocks from disk (default: %u)", DEFAULT_STOPAFTERBLOCKIMPORT));
        strUsage += HelpMessageOpt("-stopatheight", strprintf("Stop running after reaching the given height in the main chain (default: %u)", DEFAULT_STOPATHEIGHT));

        strUsage += HelpMessageOpt("-limitancestorcount=<n>", strprintf("Do not accept transactions if number of in-mempool ancestors is <n> or more (default: %u)", DEFAULT_ANCESTOR_LIMIT));
        strUsage += HelpMessageOpt("-limitancestorsize=<n>", strprintf("Do not accept transactions whose size with all in-mempool ancestors exceeds <n> kilobytes (default: %u)", DEFAULT_ANCESTOR_SIZE_LIMIT));
        strUsage += HelpMessageOpt("-limitdescendantcount=<n>", strprintf("Do not accept transactions if any ancestor would have <n> or more in-mempool descendants (default: %u)", DEFAULT_DESCENDANT_LIMIT));
        strUsage += HelpMessageOpt("-limitdescendantsize=<n>", strprintf("Do not accept transactions if any ancestor would have more than <n> kilobytes of in-mempool descendants (default: %u).", DEFAULT_DESCENDANT_SIZE_LIMIT));
        strUsage += HelpMessageOpt("-vbparams=deployment:start:end", "Use given start/end times for specified version bits deployment (regtest-only)");
    }
    strUsage += HelpMessageOpt("-debug=<category>", strprintf(_("Output debugging information (default: %u, supplying <category> is optional)"), 0) + ". " +
        _("If <category> is not supplied or if <category> = 1, output all debugging information.") + " " + _("<category> can be:") + " " + ListLogCategories() + ".");
    strUsage += HelpMessageOpt("-debugexclude=<category>", strprintf(_("Exclude debugging information for a category. Can be used in conjunction with -debug=1 to output debug logs for all categories except one or more specified categories.")));
    strUsage += HelpMessageOpt("-help-debug", _("Show all debugging options (usage: --help -help-debug)"));
    strUsage += HelpMessageOpt("-logips", strprintf(_("Include IP addresses in debug output (default: %u)"), DEFAULT_LOGIPS));
    strUsage += HelpMessageOpt("-logtimestamps", strprintf(_("Prepend debug output with timestamp (default: %u)"), DEFAULT_LOGTIMESTAMPS));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-logtimemicros", strprintf("Add microsecond precision to debug timestamps (default: %u)", DEFAULT_LOGTIMEMICROS));
        strUsage += HelpMessageOpt("-mocktime=<n>", "Replace actual time with <n> seconds since epoch (default: 0)");
        strUsage += HelpMessageOpt("-maxsigcachesize=<n>", strprintf("Limit sum of signature cache and script execution cache sizes to <n> MiB (default: %u)", DEFAULT_MAX_SIG_CACHE_SIZE));
        strUsage += HelpMessageOpt("-maxtipage=<n>", strprintf("Maximum tip age in seconds to consider node in initial block download (default: %u)", DEFAULT_MAX_TIP_AGE));
    }
    strUsage += HelpMessageOpt("-maxtxfee=<amt>", strprintf(_("Maximum total fees (in %s) to use in a single wallet transaction or raw transaction; setting this too low may abort large transactions (default: %s)"),
        CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MAXFEE)));
    strUsage += HelpMessageOpt("-printtoconsole", _("Send trace/debug info to console instead of debug.log file"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-printpriority", strprintf("Log transaction fee per kB when mining blocks (default: %u)", DEFAULT_PRINTPRIORITY));
    }
    strUsage += HelpMessageOpt("-shrinkdebugfile", _("Shrink debug.log file on client startup (default: 1 when no -debug)"));

    AppendParamsHelpMessages(strUsage, showDebug);

    strUsage += HelpMessageGroup(_("Node relay options:"));
    if (showDebug) {
        strUsage += HelpMessageOpt("-acceptnonstdtxn", strprintf("Relay and mine \"non-standard\" transactions (%sdefault: %u)", "testnet/regtest only; ", !testnetChainParams->RequireStandard()));
        strUsage += HelpMessageOpt("-incrementalrelayfee=<amt>", strprintf("Fee rate (in %s/kB) used to define cost of relay, used for mempool limiting and BIP 125 replacement. (default: %s)", CURRENCY_UNIT, FormatMoney(DEFAULT_INCREMENTAL_RELAY_FEE)));
        strUsage += HelpMessageOpt("-dustrelayfee=<amt>", strprintf("Fee rate (in %s/kB) used to defined dust, the value of an output such that it will cost more than its value in fees at this fee rate to spend it. (default: %s)", CURRENCY_UNIT, FormatMoney(DUST_RELAY_TX_FEE)));
    }
    strUsage += HelpMessageOpt("-bytespersigop", strprintf(_("Equivalent bytes per sigop in transactions for relay and mining (default: %u)"), DEFAULT_BYTES_PER_SIGOP));
    strUsage += HelpMessageOpt("-datacarrier", strprintf(_("Relay and mine data carrier transactions (default: %u)"), DEFAULT_ACCEPT_DATACARRIER));
    strUsage += HelpMessageOpt("-datacarriersize", strprintf(_("Maximum size of data in data carrier transactions we relay and mine (default: %u)"), MAX_OP_RETURN_RELAY));
    strUsage += HelpMessageOpt("-mempoolreplacement", strprintf(_("Enable transaction replacement in the memory pool (default: %u)"), DEFAULT_ENABLE_REPLACEMENT));
    strUsage += HelpMessageOpt("-minrelaytxfee=<amt>", strprintf(_("Fees (in %s/kB) smaller than this are considered zero fee for relaying, mining and transaction creation (default: %s)"),
        CURRENCY_UNIT, FormatMoney(DEFAULT_MIN_RELAY_TX_FEE)));
    strUsage += HelpMessageOpt("-whitelistrelay", strprintf(_("Accept relayed transactions received from whitelisted peers even when not relaying transactions (default: %d)"), DEFAULT_WHITELISTRELAY));
    strUsage += HelpMessageOpt("-whitelistforcerelay", strprintf(_("Force relay of transactions from whitelisted peers even if they violate local relay policy (default: %d)"), DEFAULT_WHITELISTFORCERELAY));

    strUsage += HelpMessageGroup(_("Block creation options:"));
    strUsage += HelpMessageOpt("-blockmaxweight=<n>", strprintf(_("Set maximum BIP141 block weight (default: %d)"), DEFAULT_BLOCK_MAX_WEIGHT));
    strUsage += HelpMessageOpt("-blockmaxsize=<n>", _("Set maximum BIP141 block weight to this * 4. Deprecated, use blockmaxweight"));
    strUsage += HelpMessageOpt("-blockmintxfee=<amt>", strprintf(_("Set lowest fee rate (in %s/kB) for transactions to be included in block creation. (default: %s)"), CURRENCY_UNIT, FormatMoney(DEFAULT_BLOCK_MIN_TX_FEE)));
    if (showDebug)
        strUsage += HelpMessageOpt("-blockversion=<n>", "Override block version to test forking scenarios");

    strUsage += HelpMessageGroup(_("RPC server options:"));
    strUsage += HelpMessageOpt("-server", _("Accept command line and JSON-RPC commands"));
    strUsage += HelpMessageOpt("-rest", strprintf(_("Accept public REST requests (default: %u)"), DEFAULT_REST_ENABLE));
    strUsage += HelpMessageOpt("-rpcbind=<addr>[:port]", _("Bind to given address to listen for JSON-RPC connections. This option is ignored unless -rpcallowip is also passed. Port is optional and overrides -rpcport. Use [host]:port notation for IPv6. This option can be specified multiple times (default: 127.0.0.1 and ::1 i.e., localhost, or if -rpcallowip has been specified, 0.0.0.0 and :: i.e., all addresses)"));
    strUsage += HelpMessageOpt("-rpccookiefile=<loc>", _("Location of the auth cookie (default: data dir)"));
    strUsage += HelpMessageOpt("-rpcuser=<user>", _("Username for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcpassword=<pw>", _("Password for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcauth=<userpw>", _("Username and hashed password for JSON-RPC connections. The field <userpw> comes in the format: <USERNAME>:<SALT>$<HASH>. A canonical python script is included in share/rpcuser. The client then connects normally using the rpcuser=<USERNAME>/rpcpassword=<PASSWORD> pair of arguments. This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-rpcport=<port>", strprintf(_("Listen for JSON-RPC connections on <port> (default: %u or testnet: %u)"), defaultBaseParams->RPCPort(), testnetBaseParams->RPCPort()));
    strUsage += HelpMessageOpt("-rpcallowip=<ip>", _("Allow JSON-RPC connections from specified source. Valid for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24). This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-rpcserialversion", strprintf(_("Sets the serialization of raw transaction or block hex returned in non-verbose mode, non-segwit(0) or segwit(1) (default: %d)"), DEFAULT_RPC_SERIALIZE_VERSION));
    strUsage += HelpMessageOpt("-rpcthreads=<n>", strprintf(_("Set the number of threads to service RPC calls (default: %d)"), DEFAULT_HTTP_THREADS));
    if (showDebug) {
        strUsage += HelpMessageOpt("-rpcworkqueue=<n>", strprintf("Set the depth of the work queue to service RPC calls (default: %d)", DEFAULT_HTTP_WORKQUEUE));
        strUsage += HelpMessageOpt("-rpcservertimeout=<n>", strprintf("Timeout during HTTP requests (default: %d)", DEFAULT_HTTP_SERVER_TIMEOUT));
    }

    return strUsage;
}

std::string LicenseInfo()   //版本的许可信息内容
{
    const std::string URL_SOURCE_CODE = "<https://github.com/bitcoin/bitcoin>";
    const std::string URL_WEBSITE = "<https://bitcoincore.org>";

    return CopyrightHolders(strprintf(_("Copyright (C) %i-%i"), 2009, COPYRIGHT_YEAR) + " ") + "\n" +
           "\n" +
           strprintf(_("Please contribute if you find %s useful. "
                       "Visit %s for further information about the software."),
               PACKAGE_NAME, URL_WEBSITE) +
           "\n" +
           strprintf(_("The source code is available from %s."),
               URL_SOURCE_CODE) +
           "\n" +
           "\n" +
           _("This is experimental software.") + "\n" +
           strprintf(_("Distributed under the MIT software license, see the accompanying file %s or %s"), "COPYING", "<https://opensource.org/licenses/MIT>") + "\n" +
           "\n" +
           strprintf(_("This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit %s and cryptographic software written by Eric Young and UPnP software written by Thomas Bernard."), "<https://www.openssl.org>") +
           "\n";
}

static void BlockNotifyCallback(bool initialSync, const CBlockIndex *pBlockIndex)
{
    if (initialSync || !pBlockIndex)
        return;

    std::string strCmd = gArgs.GetArg("-blocknotify", "");
    if (!strCmd.empty()) {
        boost::replace_all(strCmd, "%s", pBlockIndex->GetBlockHash().GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }
}

static bool fHaveGenesis = false;
static CWaitableCriticalSection cs_GenesisWait;
static CConditionVariable condvar_GenesisWait;

static void BlockNotifyGenesisWait(bool, const CBlockIndex *pBlockIndex)
{
    if (pBlockIndex != nullptr) {
        {
            WaitableLock lock_GenesisWait(cs_GenesisWait);
            fHaveGenesis = true;
        }
        condvar_GenesisWait.notify_all();
    }
}

struct CImportingNow
{
    CImportingNow() {
        assert(fImporting == false);
        fImporting = true;
    }

    ~CImportingNow() {
        assert(fImporting == true);
        fImporting = false;
    }
};


// If we're using -prune with -reindex, then delete block files that will be ignored by the
// reindex.  Since reindexing works by starting at block file 0 and looping until a blockfile
// is missing, do the same here to delete any later block files after a gap.  Also delete all
// rev files since they'll be rewritten by the reindex anyway.  This ensures that vinfoBlockFile
// is in sync with what's actually on disk by the time we start downloading, so that pruning
// works correctly.
void CleanupBlockRevFiles()
{
    std::map<std::string, fs::path> mapBlockFiles;

    // Glob all blk?????.dat and rev?????.dat files from the blocks directory.
    // Remove the rev files immediately and insert the blk file paths into an
    // ordered map keyed by block file index.
    LogPrintf("Removing unusable blk?????.dat and rev?????.dat files for -reindex with -prune\n");
    fs::path blocksdir = GetDataDir() / "blocks";
    for (fs::directory_iterator it(blocksdir); it != fs::directory_iterator(); it++) {
        if (fs::is_regular_file(*it) &&
            it->path().filename().string().length() == 12 &&
            it->path().filename().string().substr(8,4) == ".dat")
        {
            if (it->path().filename().string().substr(0,3) == "blk")
                mapBlockFiles[it->path().filename().string().substr(3,5)] = it->path();
            else if (it->path().filename().string().substr(0,3) == "rev")
                remove(it->path());
        }
    }

    // Remove all block files that aren't part of a contiguous set starting at
    // zero by walking the ordered map (keys are block file indices) by
    // keeping a separate counter.  Once we hit a gap (or if 0 doesn't exist)
    // start removing block files.
    int nContigCounter = 0;
    for (const std::pair<std::string, fs::path>& item : mapBlockFiles) {
        if (atoi(item.first) == nContigCounter) {
            nContigCounter++;
            continue;
        }
        remove(item.second);
    }
}

void ThreadImport(std::vector<fs::path> vImportFiles)
{
    const CChainParams& chainparams = Params();
    RenameThread("bitcoin-loadblk");

    {
    CImportingNow imp;

    // -reindex
    if (fReindex) {
        int nFile = 0;
        while (true) {
            CDiskBlockPos pos(nFile, 0);
            if (!fs::exists(GetBlockPosFilename(pos, "blk")))
                break; // No block files left to reindex
            FILE *file = OpenBlockFile(pos, true);
            if (!file)
                break; // This error is logged in OpenBlockFile
            LogPrintf("Reindexing block file blk%05u.dat...\n", (unsigned int)nFile);
            LoadExternalBlockFile(chainparams, file, &pos);
            nFile++;
        }
        pblocktree->WriteReindexing(false);
        fReindex = false;
        LogPrintf("Reindexing finished\n");
        // To avoid ending up in a situation without genesis block, re-try initializing (no-op if reindexing worked):
        LoadGenesisBlock(chainparams);
    }

    // hardcoded $DATADIR/bootstrap.dat
    fs::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (fs::exists(pathBootstrap)) {
        FILE *file = fsbridge::fopen(pathBootstrap, "rb");
        if (file) {
            fs::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LogPrintf("Importing bootstrap.dat...\n");
            LoadExternalBlockFile(chainparams, file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        } else {
            LogPrintf("Warning: Could not open bootstrap file %s\n", pathBootstrap.string());
        }
    }

    // -loadblock=
    for (const fs::path& path : vImportFiles) {
        FILE *file = fsbridge::fopen(path, "rb");
        if (file) {
            LogPrintf("Importing blocks file %s...\n", path.string());
            LoadExternalBlockFile(chainparams, file);
        } else {
            LogPrintf("Warning: Could not open blocks file %s\n", path.string());
        }
    }

    // scan for better chains in the block chain database, that are not yet connected in the active best chain
    CValidationState state;
    if (!ActivateBestChain(state, chainparams)) {
        LogPrintf("Failed to connect best block");
        StartShutdown();
        return;
    }

    if (gArgs.GetBoolArg("-stopafterblockimport", DEFAULT_STOPAFTERBLOCKIMPORT)) {
        LogPrintf("Stopping after block import\n");
        StartShutdown();
        return;
    }
    } // End scope of CImportingNow
    if (gArgs.GetArg("-persistmempool", DEFAULT_PERSIST_MEMPOOL)) {
        LoadMempool();
        fDumpMempoolLater = !fRequestShutdown;
    }
}

/** Sanity checks                                                     健全性检查
 *  Ensure that Bitcoin is running in a usable environment with all   确保比特币在一个可用的环境中运行，并提供所有必要的库支持。
 *  necessary library support.
 */
bool InitSanityCheck(void)
{
    if(!ECC_InitSanityCheck()) {    //椭圆曲线加密结果的完整性验证
        InitError("Elliptic curve cryptography sanity check failure. Aborting.");
        return false;
    }

    if (!glibc_sanity_test() || !glibcxx_sanity_test()) //验证当前运行环境是否支持C/C++运行环境
        return false;

    if (!Random_SanityCheck()) {    //验证系统的随机数生成器是否可用
        InitError("OS cryptographic RNG sanity check failure. Aborting.");
        return false;
    }

    return true;
}
//AppInitServers()函数主要就是HTTP Server的初始化，将外部的请求和内部相应的处理函数对应起来，并做好相应的任务分配。
bool AppInitServers()
{
    //首先的三行是调用了RPCServer类中的三个函数，这三个函数的功能分别是连接到各自对应的信号槽，这三个信号槽分别做了一些信号的连接
    //工作：OnRPCStarted负责将RPCNotifyBlockChange连接到NotifyBlockTip信号上；OnRPCStopped负责将连接解除，并做一些其他的清除
    //工作；OnRPCPreCommand检查在安全模式下是否有警告消息，如果有那么就抛出相应的异常。
    RPCServer::OnStarted(&OnRPCStarted);
    RPCServer::OnStopped(&OnRPCStopped);
    if (!InitHTTPServer())  //InitHTTPServer()：初始化http server。
        return false;
    if (!StartRPC())        //启动RPC服务
        return false;
    if (!StartHTTPRPC())    //启动HTTP RPC服务
        return false;
    if (gArgs.GetBoolArg("-rest", DEFAULT_REST_ENABLE) && !StartREST()) //启动REST
        return false;
    if (!StartHTTPServer()) //启动HTTP server
        return false;
    return true;
}
// 该函数主要是根据参数命令，改变当前的参数，并把相应的信息打印到日志文件中。其中还涉及到一些网络中IP地址的监听设置方法、白名单的禁用和
// 启用情况等。其实就是日志文件中初始化日志后（即版本信息打印后）的大量的日志内容。
// Parameter interaction based on rules
void InitParameterInteraction()
{
    // when specifying an explicit binding address, you want to listen on it 当显示指定了绑定地址后，即使指定了-connect和-proxy参数信息，程序将会接受来自外部的连接，并监听该地址。
    // even when -connect or -proxy is specified                             通过参数-bind或-whitebind这两个参数设置，并通过SoftSetBoolArg()函数实现了-listen参数的设置，把它设置成true，代表要监听设置的外部连接IP地址。
    if (gArgs.IsArgSet("-bind")) {      //(1)绑定并监听地址
        if (gArgs.SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -bind set -> setting -listen=1\n", __func__);
    }
    if (gArgs.IsArgSet("-whitebind")) {
        if (gArgs.SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -whitebind set -> setting -listen=1\n", __func__);
    }

    //首先判断参数命令中是否含有-connect参数，如果有将-dnsseed（使用DNS查找节点）和-listen（即接受来自外部的连接，并对其进行监听）设置为true。并进行日志打印。注意：此处代码的有效执行是在为设置-bind和-whitebind参数的情况下进行的。
    if (gArgs.IsArgSet("-connect")) {   //(2)连接可信的节点
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        if (gArgs.SoftSetBoolArg("-dnsseed", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -dnsseed=0\n", __func__);
        if (gArgs.SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -listen=0\n", __func__);
    }

    //设置代理参数的目的是为了保护隐私，则此处将-listen、-upnp以及-discover均设置为false，也就是说比特币后台进程只使用代理提供的监听地址与端口，并且不去查找默认的监听地址。这里的upnp代表的意思是使用全局即插即用（UPNP）映射监听端口，默认不使用。注意：此处代码的有效执行也是在为设置-bind和-whitebind参数的情况下进行的。
    if (gArgs.IsArgSet("-proxy")) {     //(3)代理模式
        // to protect privacy, do not listen by default if a default proxy server is specified
        if (gArgs.SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -listen=0\n", __func__);
        // to protect privacy, do not use UPNP when a proxy is set. The user may still specify -listen=1
        // to listen locally, so don't rely on this happening through -listen below.
        if (gArgs.SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -upnp=0\n", __func__);
        // to protect privacy, do not discover addresses by default
        if (gArgs.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -discover=0\n", __func__);
    }

    //当不监听时，不要映射端口或尝试检索公共IP。就是如果监听参数设置为false，则upnp（端口）、discover（自动发现默认地址）以及listenonion（匿名地址监听）均设置为false。
    if (!gArgs.GetBoolArg("-listen", DEFAULT_LISTEN)) { //(4)监听设置处理
        // do not map ports or try to retrieve public IP when not listening (pointless)
        if (gArgs.SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -upnp=0\n", __func__);
        if (gArgs.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -discover=0\n", __func__);
        if (gArgs.SoftSetBoolArg("-listenonion", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -listenonion=0\n", __func__);
    }

    //如果显示指定了公共IP地址，那么bitcoind就不需要查找其他监听地址。
    if (gArgs.IsArgSet("-externalip")) {        //(5)外部IP参数处理
        // if an explicit public IP is specified, do not try to find others
        if (gArgs.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -externalip set -> setting -discover=0\n", __func__);
    }
    
    // disable whitelistrelay in blocksonly mode
    // DEFAULT_BLOCKSONLY在net.h中定义，默认值为false。表示在blocksonly模式（区块模式）下禁用whitelistrelay。即在区块模式下白名单列表失效。
    if (gArgs.GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY)) {  //(6) 区块模式参数设置
        if (gArgs.SoftSetBoolArg("-whitelistrelay", false))
            LogPrintf("%s: parameter interaction: -blocksonly=1 -> setting -whitelistrelay=0\n", __func__);
    }
    
    // Forcing relay from whitelisted hosts implies we will accept relays from them in the first place.
    // 强制白名单节点连接参数处理意味着比特币网络中的信息将优先在白名单节点间传递。
    if (gArgs.GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY)) {//(7)强制白名单节点连接参数处理
        if (gArgs.SoftSetBoolArg("-whitelistrelay", true))
            LogPrintf("%s: parameter interaction: -whitelistforcerelay=1 -> setting -whitelistrelay=1\n", __func__);
    }

    //区块大小是设置默认的矿工产生区块的大小。
    if (gArgs.IsArgSet("-blockmaxsize")) {  //(8)区块大小设置
        unsigned int max_size = gArgs.GetArg("-blockmaxsize", 0);
        if (gArgs.SoftSetArg("blockmaxweight", strprintf("%d", max_size * WITNESS_SCALE_FACTOR))) {
            LogPrintf("%s: parameter interaction: -blockmaxsize=%d -> setting -blockmaxweight=%d (-blockmaxsize is deprecated!)\n", __func__, max_size, max_size * WITNESS_SCALE_FACTOR);
        } else {
            LogPrintf("%s: Ignoring blockmaxsize setting which is overridden by blockmaxweight", __func__);
        }
    }
}

static std::string ResolveErrMsg(const char * const optname, const std::string& strBind)
{
    return strprintf(_("Cannot resolve -%s address: '%s'"), optname, strBind);
}
//函数作用的结果是把数据存储在debug.log文件中，该文件在ubuntu系统是在$HOME/.bitcoin/文件夹中，接下来对它初始化实现的6个设置内容较详细说明
void InitLogging()  //参数DEFAULT_LOGTIMESTAMPS、DEFAULT_LOGTIMEMICROS、DEFAULT_LOGIPS在util.h中有定义
{
    //检测参数命令中是否含有-printtoconsole命令，如果有则让日志信息发送跟踪/调试信息到控制台中，但默认是false，即默认只是记录在日志文件debug.log中，而不是在控制台中显示；
    fPrintToConsole = gArgs.GetBoolArg("-printtoconsole", false);
    //检测参数命令中是否含有-logtimestamps，该参数的含义是在日志中打印时间戳，由上面的补充内容知道默认是在日志文件中打印时间戳的；
    fLogTimestamps = gArgs.GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS);
    //检测参数命令中是否含有-logtimemicros，该参数的含义是打印日志单位精确到微妙（μs），由上面的补充内容知道默认是false，即默认初始化日志文件精确到秒（s）；
    fLogTimeMicros = gArgs.GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS);
    //检测参数命令中是否含有-logips，该参数的含义是打印IP地址，由上面的补充内容知道默认是false，即默认在日志文件中是不打印IP地址的；
    fLogIPs = gArgs.GetBoolArg("-logips", DEFAULT_LOGIPS);

    LogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");  //在日志文件中空19行
    std::string version_string = FormatFullVersion();       //打印“Bitcoin version”，并紧跟上比特币客户端的版本信息。
#ifdef DEBUG
    version_string += " (debug build)";
#else
    version_string += " (release build)";
#endif
    LogPrintf(PACKAGE_NAME " version %s\n", version_string);
}

namespace { // Variables internal to initialization process only

int nMaxConnections;
int nUserMaxConnections;
int nFD;
ServiceFlags nLocalServices = ServiceFlags(NODE_NETWORK | NODE_NETWORK_LIMITED);

} // namespace

[[noreturn]] static void new_handler_terminate()
{
    // Rather than throwing std::bad-alloc if allocation fails, terminate
    // immediately to (try to) avoid chain corruption.
    // Since LogPrintf may itself allocate memory, set the handler directly
    // to terminate first.
    std::set_new_handler(std::terminate);
    LogPrintf("Error: Out of memory. Terminating.\n");

    // The log was successful, terminate now.
    std::terminate();
};
//主要作用是：安装网络环境，挂接事件处理器等
bool AppInitBasicSetup()
{
    // ********************************************************* Step 1: setup  第1步：安装。

    //(1)警告消息处理并解决异常错误捕获问题
    //由#ifdef的条件判断标识符_MSC_VER可以知道这段代码是针对微软的VS开发环境而设置的，而在其他的编译环境下这段代码是不会被执行编译的。
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise                           //关闭微软堆转储的噪音
    //①_CrtSetReportMode：设置开发编译环境报告类型为警告，报告的输出方式为文件输出。
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    //②_CrtSetReportFile：创建一个空的文件，把警告消息输出到这个文件中。即关闭警告消息。
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, 0));
    // Disable confusing "helpful" text message on abort, Ctrl-C    //在abort上禁用令人困惑的“helpful”文本消息，ctrl-c
    //③_set_abort_behavior：处理在VS环境下的只会强制把异常抛给默认的调试器的问题，用该函数把异常抛给异常捕获函数。
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif

    //(2)数据执行保护（DEP）功能处理
    //数据执行保护（DEP）的目的是为了防止病毒或其他安全威胁造成损害，Windows XP SP2、WinXP SP3, WinVista >= SP1, Win Server 2008
    //使用了数据执行保护(DEP)功能，而GCCs winbase.h将该功能限制在_WIN32_WINNT >= 0x0601 (Windows 7)才能使用，所以在代码中强制定义
    //了宏定义。通过函数指针获取Kernel32.dll中的SetProcessDEPPolicy函数对象，实现DEP功能的开启。
#ifdef WIN32
    // Enable Data Execution Prevention (DEP)                                       打开DEP
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008   最小支持OS版本:WinXP SP3,WinVista >= SP1,Win Server 2008
    // A failure is non-critical and needs no further attention!                    失败是不重要的，不需要进一步的关注!
#ifndef PROCESS_DEP_ENABLE
    // We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
    // which is not correct. Can be removed, when GCCs winbase.h is fixed!          GCCs winbase.h将该功能限制在_WIN32_WINNT >= 0x0601 (Windows 7)才能使用，所以在代码中强制定义了宏定义。
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != nullptr) setProcDEPPol(PROCESS_DEP_ENABLE);
#endif

    //(3)初始化网络连接
    if (!SetupNetworking())
        return InitError("Initializing networking failed");

    //(4)信号处理设置
#ifndef WIN32
    //文件创建权限(先是判断是否设置了-sysperms参数。如果设置了该参数，则返回设置的状态值；如果没有（false），则执行
    //命令：umask(077);。umask()函数用于设置文件与文件夹使用权限，此处077代表---rwxrwx，表示owner没有任何权限，group和
    //other有完全的操作权限。)
    if (!gArgs.GetBoolArg("-sysperms", false)) {
        umask(077);
    }

    // Clean shutdown on SIGTERM                    彻底关闭信号SIGTERM
    registerSignalHandler(SIGTERM, HandleSIGTERM);  //终止信号处理
    registerSignalHandler(SIGINT, HandleSIGTERM);   //中断信号处理

    // Reopen debug.log on SIGHUP                   挂起信号SIGHUP并重新打开debug.log文件
    registerSignalHandler(SIGHUP, HandleSIGHUP);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    // 忽略信号SIGPIPE，否则如果客户端意外关闭，它将使守护进程关闭
    signal(SIGPIPE, SIG_IGN);
#endif

    //(5)内存分配失败处理(其中new_handler_terminate函数主要是为了防止影响区块链被破坏，通过执行terminate命令，直接终止程序的方式
    //解决内存分配失败导致的错误，并且进行日志打印；而set_new_handler()函数是C++中常用的内存异常处理函数)
    std::set_new_handler(new_handler_terminate);

    return true;
}

bool AppInitParameterInteraction()
{
    const CChainParams& chainparams = Params();
    // ********************************************************* Step 2: parameter interactions 第二步：参数的相互作用。

    // also see: InitParameterInteraction()
    //（1）prune和txindex参数不能同时设置:所以这两个参数存在不兼容的问题，要让它们不能同时设置，如果同时设置了会报错，并退出程序。
    // if using block pruning, then disallow txindex            如果使用区块修剪，那么就不允许txindex
    //①prune参数：这个修剪的对象是Merkle Tree，目的是为了节省存储空间。在比特币中默认是不修剪的，除非对它专门进行了开启设置。
    if (gArgs.GetArg("-prune", 0)) {
        //②txindex参数：这个参数作用是维护一个全交易索引，是要全保留交易信息的。
        if (gArgs.GetBoolArg("-txindex", DEFAULT_TXINDEX))
            return InitError(_("Prune mode is incompatible with -txindex."));
    }

    //（2）当监听外部连接未设置时bind和whitebind参数不会设置
    // -bind and -whitebind can't be set when not listening  当`-listen`参数为0时`-bind`或`-whitebind`不能被设置
    // 这段代码主要是判断当参数-listen设置为0时，参数-bind或-whitebind是否有非0设置，如果有，则会报错，并退出程序。
    size_t nUserBind = gArgs.GetArgs("-bind").size() + gArgs.GetArgs("-whitebind").size();
    if (nUserBind != 0 && !gArgs.GetBoolArg("-listen", DEFAULT_LISTEN)) {
        return InitError("Cannot set -bind or -whitebind together with -listen=0");
    }

    //（3）确保有足够可用的文件描述符
    // Make sure enough file descriptors are available
    int nBind = std::max(nUserBind, size_t(1));
    // DEFAULT_MAX_PEER_CONNECTIONS：定义位于net.h，代表了最大可维护的节点连接数，默认值为125。
    nUserMaxConnections = gArgs.GetArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS);
    nMaxConnections = std::max(nUserMaxConnections, 0);

    // Trim requested connection counts, to fit into system limitations     修剪请求的连接数，以适应系统的限制。
    // FD_SETSIZE：定义位于compat.h，代表可包含的最大文件描述符的个数，默认为1024。
    nMaxConnections = std::max(std::min(nMaxConnections, (int)(FD_SETSIZE - nBind - MIN_CORE_FILEDESCRIPTORS - MAX_ADDNODE_CONNECTIONS)), 0);
    // MIN_CORE_FILEDESCRIPTORS：定义于init.cpp，代表了最小核心文件描述符个数，window下默认为0，linux下为默认为150。
    // MAX_ADDNODE_CONNECTIONS：定义位于net.h，代表了最大增加节点连接数，默认为8。
    nFD = RaiseFileDescriptorLimit(nMaxConnections + MIN_CORE_FILEDESCRIPTORS + MAX_ADDNODE_CONNECTIONS);
    if (nFD < MIN_CORE_FILEDESCRIPTORS)
        return InitError(_("Not enough file descriptors available."));
    nMaxConnections = std::min(nFD - MIN_CORE_FILEDESCRIPTORS - MAX_ADDNODE_CONNECTIONS, nMaxConnections);

    if (nMaxConnections < nUserMaxConnections)
        InitWarning(strprintf(_("Reducing -maxconnections from %d to %d, because of system limitations."), nUserMaxConnections, nMaxConnections));
    //第二步总结：主要是进一步的参数交互设置：区块裁剪prune和txindex的冲突检查、listen参数关闭时bind参数或whitebind参数检测、
    //文件描述符的限制检查。总之是对参数设置检查，避免运行时出现故障。

    // ********************************************************* Step 3: parameter-to-internal-flags 第三步：参数转换为内部变量
    //（1）-debug：标志参数。帮助文件中的解释为：输出调试信息。此处设置成：如果-debug=0或者设置了-nodebug参数，则关闭调试信息；如果-debug=1则输出调试信息。
    if (gArgs.IsArgSet("-debug")) {
        // Special-case: if -debug=0/-nodebug is set, turn off debugging messages
        const std::vector<std::string> categories = gArgs.GetArgs("-debug");

        if (std::none_of(categories.begin(), categories.end(),
            [](std::string cat){return cat == "0" || cat == "none";})) {
            for (const auto& cat : categories) {
                uint32_t flag = 0;
                if (!GetLogCategory(&flag, &cat)) {
                    InitWarning(strprintf(_("Unsupported logging category %s=%s."), "-debug", cat));
                    continue;
                }
                logCategories |= flag;
            }
        }
    }

    // Now remove the logging categories which were explicitly excluded
    //（2）-debugexclude：帮助文件中的解释为：排除类别的调试信息。可以与-debug=1一起使用，以输出除一个或多个指定类别之外的所有类别的调试日志。此处设置成：如果该参数设置了，就在调试日志中删除设置的日志类型。
    for (const std::string& cat : gArgs.GetArgs("-debugexclude")) {
        uint32_t flag = 0;
        if (!GetLogCategory(&flag, &cat)) {
            InitWarning(strprintf(_("Unsupported logging category %s=%s."), "-debugexclude", cat));
            continue;
        }
        logCategories &= ~flag;
    }

    // Check for -debugnet
    //（3）-debugnet：标志参数。比特币程序目前已经不支持这个参数，需要用-debug=net替代。此处设置成：如果检测该参数存在，发出警告信息。
    if (gArgs.GetBoolArg("-debugnet", false))
        InitWarning(_("Unsupported argument -debugnet ignored, use -debug=net."));
    // Check for -socks - as this is a privacy risk to continue, exit here
    //（4）-socks：标志参数。比特币程序目前已经不支持这个参数，socket通讯目前只支持SOCKS5代理协议。此处设置成：如果检测该参数存在，抛给错误信息。
    if (gArgs.IsArgSet("-socks"))
        return InitError(_("Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported."));
    // Check for -tor - as this is a privacy risk to continue, exit here
    //（5）-tor：标志参数。tor的英文全称为The Onion Router，即第二代洋葱路由（onion routing），用于匿名通信。比特币程序目前已经不支持这个参数，要使用-onion参数代替。此处设置成：如果检测该参数存在，抛给错误信息。
    if (gArgs.GetBoolArg("-tor", false))
        return InitError(_("Unsupported argument -tor found, use -onion."));
    //（6）-benchmark：标志参数。现在比特币中-benchmark已被忽略，使用debug=bench代替。此处设置成：如果检测该参数存在，发出警告信息。
    if (gArgs.GetBoolArg("-benchmark", false))
        InitWarning(_("Unsupported argument -benchmark ignored, use -debug=bench."));
    //（7）-whitelistalwaysrelay：标志参数。现在比特币中-whitelistalwaysrelay已被忽略，使用-whitelistrelay、-whitelistforcerelay两个参数之一或共同使用来代替。-whitelistrelay参数的意义是节点间的通信优先在白名单节点之间实现。此处设置成：如果检测该参数存在，发出警告信息
    if (gArgs.GetBoolArg("-whitelistalwaysrelay", false))
        InitWarning(_("Unsupported argument -whitelistalwaysrelay ignored, use -whitelistrelay and/or -whitelistforcerelay."));
    //（8）-blockminsize：标志参数。-blockminsize参数也已被弃用。此处设置成：如果检测该参数存在，发出警告信息。
    if (gArgs.IsArgSet("-blockminsize"))
        InitWarning("Unsupported argument -blockminsize ignored.");

    // Checkmempool and checkblockindex default to true in regtest mode
    //（9）-checkmempool：检测交易池。帮助文件中的解释为：每n次事件检测一次。此处设置成：根据网络的不同设置不同值——私有网络默认开启，主网和测试网默认关闭。（检测程序是存在资源消耗的，会影响程序的运行效率。）
    int ratio = std::min<int>(std::max<int>(gArgs.GetArg("-checkmempool", chainparams.DefaultConsistencyChecks() ? 1 : 0), 0), 1000000);
    if (ratio != 0) {
        mempool.setSanityCheck(1.0 / ratio);
    }
    //（10）-checkblockindex：区块索引检测。帮助文件中的解释为：对mapBlockIndex, setBlockIndexCandidates, chainActive和
    // mapBlocksUnlinked进行完整的一致性检查。和还设置-checkmempool同样设置。类似-checkmempool的设置：只有在私有网模式下才
    // 会进行区块索引的检测，其他两个网默认是不检测的。（例如如果根据是私有网络设置成了true，会修改validation.h中的全局变量
    // fCheckBlockIndex，validation.cpp中的CheckBlockIndex()函数会使用该变量，将实现了区块索引信息的验证。）
    fCheckBlockIndex = gArgs.GetBoolArg("-checkblockindex", chainparams.DefaultConsistencyChecks());
    //（11）-checkpoints：检测点参数提示参数。帮助文件中的解释为：禁用对已知链历史昂贵的验证。这个主要是移除检查点的意思。此处设置成：把该参数的结果（默认是true）返回给全局变量fCheckpointsEnabled。
    fCheckpointsEnabled = gArgs.GetBoolArg("-checkpoints", DEFAULT_CHECKPOINTS_ENABLED);

    //（12）-assumevalid：哈希假定有效参数。帮助文件中的解释为：如果这个块在链中，假设它和它的父块是有效的，并且可能跳过他们的脚本
    //验证。此处设置成：①获得链上共识参数：通过chainparams.GetConsensus()函数获得链上共识参数。②默认假定有效对象：默认假定有效对象
    //主要是需要存储二进制值，二进制数为区块的哈希值。③获取哈希值：通过GetHex()函数获取哈希值的十六进值。
    hashAssumeValid = uint256S(gArgs.GetArg("-assumevalid", chainparams.GetConsensus().defaultAssumeValid.GetHex()));
    if (!hashAssumeValid.IsNull())
        LogPrintf("Assuming ancestors of block %s have valid signatures.\n", hashAssumeValid.GetHex());
    else
        LogPrintf("Validating signatures for all blocks.\n");

    //（13）-minimumchainwork：最小链工作。帮助文件中的解释为：假设在十六进制的有效链上存在最小工作。此处设置成：只对最小链工作的数据
    // 部分进行检查（如对参数值0X002101540只检查数据头部的0X00如果符合要求，则无错误，反之报错），能够减少检查点的需要。
    if (gArgs.IsArgSet("-minimumchainwork")) {
        const std::string minChainWorkStr = gArgs.GetArg("-minimumchainwork", "");
        if (!IsHexNumber(minChainWorkStr)) {
            return InitError(strprintf("Invalid non-hex (%s) minimum chain work value specified", minChainWorkStr));
        }
        nMinimumChainWork = UintToArith256(uint256S(minChainWorkStr));
    } else {
        nMinimumChainWork = UintToArith256(chainparams.GetConsensus().nMinimumChainWork);
    }
    LogPrintf("Setting nMinimumChainWork=%s\n", nMinimumChainWork.GetHex());
    if (nMinimumChainWork < UintToArith256(chainparams.GetConsensus().nMinimumChainWork)) {
        LogPrintf("Warning: nMinimumChainWork set below default value of %s\n", chainparams.GetConsensus().nMinimumChainWork.GetHex());
    }

    // mempool limits
    //（14）-maxmempool：交易池大小限定参数。帮助文件中的解释为：将交易内存池保持在n兆字节以下。此处设置成：
    // 交易池最大容量是该参数设置的值*1000000（该参数默认值是300）。
    int64_t nMempoolSizeMax = gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    //（15）-limitdescendantsize：交易池大小限定参数。帮助文件中的解释为：如果任何父节点在交易池中有超过<n>KB的子节点，
    // 则不接受交易。此处设置成：交易池最小容量是该参数设置的值*1000*40（该参数默认值是101）。
    int64_t nMempoolSizeMin = gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000 * 40;
    //这两个交易池大小限定参数是判断交易池的最大容量要大于0且小于交易池最小容量，否则报错。
    if (nMempoolSizeMax < 0 || nMempoolSizeMax < nMempoolSizeMin)
        return InitError(strprintf(_("-maxmempool must be at least %d MB"), std::ceil(nMempoolSizeMin / 1000000.0)));
    // incremental relay fee sets the minimum feerate increase necessary for BIP 125 replacement in the mempool
    // and the amount the mempool min fee increases above the feerate of txs evicted due to mempool limiting.
    //（16）-incrementalrelayfee：交易费增长量。帮助文件中的解释为：设置最低收费标准，增加formempool限制或bip125替换成本。
    // 此处对它设置注释大概可以理解为：incrementalRelayFee的功能是设置最小费率增长量，通过设置交易费增长量与交易最小费的目
    // 的考虑交易池的容量限制，排除一些交易费过低的交易，即将其交易退回。该值可理解为最小交易费用设置的最低值，因为交易池中交
    // 易费的增量是以incrementalRelayFee为基础的，所以每笔交易费必须大于等于incrementalRelayFee，也就是说最小交易费也必须
    // 大于等于该值。此处设置成：先通过IsArgSet()函数判断是否设置了-incrementalrelayfee参数，如果设置了，则通过ParseMoney()
    // 函数将输入的以字符串表达的交易增长费转换为数字型的增长交易费（ParseMoney()与其反向求解的FormatMoney()函数均定义
    // 在utilmoneystr.h，这两个函数FormatMoney()是将数字转换为字符串，ParseMoney()是将字符串转换为数字。），如果传入的金额无效
    // 则退出程序，反之为incrementalRelayFee赋值，为其费率值赋予传入的数值。通过CFeeRate()（amount.h中定义与注释）可以知道
    // 传入的n的单位为每千字节需要n聪的金额。
    if (gArgs.IsArgSet("-incrementalrelayfee"))
    {
        CAmount n = 0;
        if (!ParseMoney(gArgs.GetArg("-incrementalrelayfee", ""), n))
            return InitError(AmountErrMsg("incrementalrelayfee", gArgs.GetArg("-incrementalrelayfee", "")));
        incrementalRelayFee = CFeeRate(n);
    }

    // -par=0 means autodetect, but nScriptCheckThreads==0 means no concurrency
    //（17）-par：验证脚本线程数。帮助文件中的解释为：设置脚本验证线程的数量。此处设置成：由注释知（-par=0时意味着程序自动根据机
    // 器情况自动检测线程数，而nScriptCheckThreads==0意味着将不按并发方式实现脚本验证，即脚本验证线程数为0），该段程序就是把-par的
    // 设置参数（默认是0，意味默认选择自动检测验证线程数）赋值给nScriptCheckThreads，然后判断这个变量的值，
    // 当nScriptCheckThreads输入值为0或负数时，程序将通过GetNumCores()函数获取程序运行机器能提供的线程数，
    // 然后nScriptCheckThreads加上获取的线程数获得脚本验证的线程数，新的值再次判断，最后的nScriptCheckThreads值是0或者16。
    nScriptCheckThreads = gArgs.GetArg("-par", DEFAULT_SCRIPTCHECK_THREADS);
    if (nScriptCheckThreads <= 0)
        nScriptCheckThreads += GetNumCores();
    if (nScriptCheckThreads <= 1)
        nScriptCheckThreads = 0;
    else if (nScriptCheckThreads > MAX_SCRIPTCHECK_THREADS)
        nScriptCheckThreads = MAX_SCRIPTCHECK_THREADS;

    // block pruning; get the amount of disk space (in MiB) to allot for block & undo files
    //（18）-prune：区块裁剪（区块修剪；获取磁盘空间（MiB单位）为了分配给区块和撤销文件）。区块裁剪是针对预先设定的存储容量来进行的，
    // 即根据客户端所在计算机中的存储情况进行设定，如果超过了设定值，将进行区块裁剪，以防超过设定值，并且该设定值为MiB单位。此处设置
    // 流程：首先是获取-prune参数值（默认为0）并赋值给nPruneArg变量；然后判断nPruneArg是否小于0，如果小于0，程序将出错，并退出
    //（因为我们知道如果nPruneArg小于0，表示不会为区块提供存储空间了，程序将无法正常工作）；如果nPruneArg大于0，则计算该值所对应的
    // 字节数，并把计算后的值赋值给nPruneTarget变量；然后判断-prune是否为1，如果为1，打印日志，程序不会自动对区块进行裁剪，需要通过
    // RPC命令pruneblockchain对相应区块进行裁剪，并且设置裁剪模式fPruneMode为true；如果-prune不为1，首先判断设定的裁剪值是否小于程
    // 序默认设置的用于存储区块的最小硬盘存储空间MIN_DISK_SPACE_FOR_BLOCK_FILES（默认为550 * 1024 * 1024 = 550MiB，即为区块设定的
    // 最小存储空间为550MiB）如果小于，会报错。如果不小于会正常运行，并把裁剪模式fPruneMode设置为true。
    int64_t nPruneArg = gArgs.GetArg("-prune", 0);
    if (nPruneArg < 0) {
        return InitError(_("Prune cannot be configured with a negative value."));
    }
    nPruneTarget = (uint64_t) nPruneArg * 1024 * 1024;
    if (nPruneArg == 1) {  // manual pruning: -prune=1
        LogPrintf("Block pruning enabled.  Use RPC call pruneblockchain(height) to manually prune block and undo files.\n");
        nPruneTarget = std::numeric_limits<uint64_t>::max();
        fPruneMode = true;
    } else if (nPruneTarget) {
        if (nPruneTarget < MIN_DISK_SPACE_FOR_BLOCK_FILES) {
            return InitError(strprintf(_("Prune configured below the minimum of %d MiB.  Please use a higher number."), MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
        }
        LogPrintf("Prune configured to target %uMiB on disk for block and undo files.\n", nPruneTarget / 1024 / 1024);
        fPruneMode = true;
    }

    //（19）-timeout：节点超时参数。帮助文件中的解释为：指定连接超时的时间，以毫秒为单位。这个参数的意义在于：比特币网络中新加入的节点
    // 都会去寻找节点，加入比特币P2P网络中，与其他节点完成同步操作。但是在网络中寻找节点，并建立连接是有时间限制的，即会出现连接超时的
    // 问题。而这个超时时间就会用该参数设置，默认为5000毫秒，最小为1毫秒。此处设置成：（因为它的最小为值1）判断如果该值小于1，则把它设
    // 置成默认值。
    nConnectTimeout = gArgs.GetArg("-timeout", DEFAULT_CONNECT_TIMEOUT);
    if (nConnectTimeout <= 0)
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;

    //（20）-minrelaytxfee：最小交易费率。帮助文件中的解释为：比这个费用更低被认为是对传播交易、挖矿和创建交易的零费用。（该费率为
    // 每千字节所需的最小费率，该费率值的设置对于矿工来说很重要，需谨慎设置，切忌设置为为0，因为如果设置为0时，每个被挖出的区块中都
    // 将会被塞满1聪交易费的交易，这将会使得矿工入不敷出。所以最低交易费必须高于处理交易所需成本）此处设置成：如果该参数有值（默认为
    // 1000），得到该值，并用函数ParseMoney()转换为数字，赋值给n；判断该值如果为0，会报错；在CWallet::ParameterInteraction()完
    // 成之后进行高费用检查；只允许incrementalRelayFee来控制上面的两个操作。
    if (gArgs.IsArgSet("-minrelaytxfee")) {
        CAmount n = 0;
        if (!ParseMoney(gArgs.GetArg("-minrelaytxfee", ""), n)) {
            return InitError(AmountErrMsg("minrelaytxfee", gArgs.GetArg("-minrelaytxfee", "")));
        }
        // High fee check is done afterward in WalletParameterInteraction()
        ::minRelayTxFee = CFeeRate(n);
    } else if (incrementalRelayFee > ::minRelayTxFee) {
        // Allow only setting incrementalRelayFee to control both
        ::minRelayTxFee = incrementalRelayFee;
        LogPrintf("Increasing minrelaytxfee to %s to match incrementalrelayfee\n",::minRelayTxFee.ToString());
    }

    // Sanity check argument for min fee for including tx in block
    // TODO: Harmonize which arguments need sanity checking and where that happens
    //（21）-blockmintxfee：区块中打包交易的最小费用值信息。帮助文件中的解释为：设置在块创建中包含的交易的最低收费率。即通过挖矿
    // 发现的区块打包交易的最低费率，默认为1000聪。此处设置成：由开始的注释（对包括tx在内的区块最小费用进行完整性检查。TODO:协调
    // 需要检查的参数和发生的地方）知道设置该参数的目的。那么判断该值是否为0，若为0则报错；不为0继续。
    if (gArgs.IsArgSet("-blockmintxfee"))
    {
        CAmount n = 0;
        if (!ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n))
            return InitError(AmountErrMsg("blockmintxfee", gArgs.GetArg("-blockmintxfee", "")));
    }

    // Feerate used to define dust.  Shouldn't be changed lightly as old
    // implementations may inadvertently create non-standard transactions
    //（22）-dustrelayfee：灰尘交易。帮助文件中的解释为：这个费用率用来定义灰尘，其输出的价值将超过其在费用中所花费的费用。
    // dustrelayfee为那些交易费用很低的交易，可以形象得理解为灰尘、忽略不计的费用。此处设置成：判断它的值（默认为1000聪），
    // 如果为0则报错；如果不为0则把值赋值给全局变量dustRelayFee。
    if (gArgs.IsArgSet("-dustrelayfee"))
    {
        CAmount n = 0;
        if (!ParseMoney(gArgs.GetArg("-dustrelayfee", ""), n) || 0 == n)
            return InitError(AmountErrMsg("dustrelayfee", gArgs.GetArg("-dustrelayfee", "")));
        dustRelayFee = CFeeRate(n);
    }

    //（23）-acceptnonstdtxn：非标准交易。含义是：比特币网络中是否需要非标准交易。是否接受标准交易主要看当前运行的是什么网络
    //（主网、测试网、私有网），这3种网络对是否需要标准交易是有默认要求的。主网只接受标准交易，测试网与私有网可以接受非标准交易。
    // 该参数根据不同网络默认值让布尔变量fRequireStandard记录。
    fRequireStandard = !gArgs.GetBoolArg("-acceptnonstdtxn", !chainparams.RequireStandard());
    if (chainparams.RequireStandard() && !fRequireStandard)
        return InitError(strprintf("acceptnonstdtxn is not currently supported for %s chain", chainparams.NetworkIDString()));
    //（24）-bytespersigop：签名操作字节数。帮助文件中的解释为：用于传播和挖矿的交易数据的每个签名的等效字节数。此处设置成：把此
    // 参数的值（默认为20）赋值给全局变量nBytesPerSigOp。
    nBytesPerSigOp = gArgs.GetArg("-bytespersigop", nBytesPerSigOp);

    //由代码可以知道当判断条件满足时就直接返回false，下面的代码将不会被执行。通过学习知道这个判断的函数就是判断是否成功启动钱包功能。
#ifdef ENABLE_WALLET
    if (!WalletParameterInteraction())
        return false;
#endif

    //（25）-permitbaremultisig：交易相关参数。该参数代表的含义是允许发送非P2SH脚本多重签名（baremultisig）。默认为true，
    // 即默认允许非P2SH多重签名的交易在全网传播。
    fIsBareMultisigStd = gArgs.GetBoolArg("-permitbaremultisig", DEFAULT_PERMIT_BAREMULTISIG);
    //（26）-datacarrier：交易相关参数。该参数表示是否可以传播和挖矿是否包含交易意外的数据内容，其默认值为true，即是允许的。
    fAcceptDatacarrier = gArgs.GetBoolArg("-datacarrier", DEFAULT_ACCEPT_DATACARRIER);
    //（27）-datacarriersize：交易相关参数。该参数表示包含数据的交易大小默认值，其默认值为83字节。该参数和上面的参数-datacarrier一起
    // 作用，主要是先赋值给fAcceptDatacarrier与nMaxDatacarrierBytes，然后通过分析二者的值判断交易是否为标准交易，防止DoS攻击。
    nMaxDatacarrierBytes = gArgs.GetArg("-datacarriersize", nMaxDatacarrierBytes);

    // Option to startup with mocktime set (used for regression testing):
    //（28）-mocktime：单元测试参数处理。此处的-mocktime为用于测试网络起始时间，通过SetMockTime()函数设置测试网络的起始时间。
    // 在非测试模式为无操作的设置，在测试模式下有值。
    SetMockTime(gArgs.GetArg("-mocktime", 0)); // SetMockTime(0) is a no-op 

    //（29）-peerbloomfilters：Bloom过滤参数处理。帮助文件中的解释为：支持针对区块和交易的bloom过滤。默认是true，即默认是支持
    // bloom过滤器的。此处设置成：在支持该过滤器的前提下，程序中设置了当前运行节点的服务模式。
    if (gArgs.GetBoolArg("-peerbloomfilters", DEFAULT_PEERBLOOMFILTERS))
        nLocalServices = ServiceFlags(nLocalServices | NODE_BLOOM);

    //（30）-rpcserialversion：帮助文件中的解释为：在非冗长模式、非隔离见证模式（0）或隔离见证（1）模式下原始交易或区块以十六进
    // 制序列化方式呈现。默认值为1，则在隔离见证模式下呈现。此处设置成：如果值小于0或大于1，则报错。
    if (gArgs.GetArg("-rpcserialversion", DEFAULT_RPC_SERIALIZE_VERSION) < 0)
        return InitError("rpcserialversion must be non-negative.");

    if (gArgs.GetArg("-rpcserialversion", DEFAULT_RPC_SERIALIZE_VERSION) > 1)
        return InitError("unknown rpcserialversion requested.");

    //（31）-maxtipage：该参数的用途是当我们运行的节点包含的区块信息落后于主网最长时间24小时后，我们的比特币客户端将
    //进行Initial block download（IBD）操作，进行区块同步下载。并不是说只在刚启动时执行IBD操作，而是当我们的节点信息
    //比全网最长链落后了24小时或者144个块时就会执行IBD操作。
    nMaxTipAge = gArgs.GetArg("-maxtipage", DEFAULT_MAX_TIP_AGE);

    //（32）-mempoolreplacement：该参数作用是可以在拥有全节点的客户端替换交易池中的交易，即针对同一输入，可以用花费
    // 了该输入的一部分或全部金额的交易替换交易池中的交易。默认为true，即交易池中的交易按照既定规则是可以被替换的。
    fEnableReplacement = gArgs.GetBoolArg("-mempoolreplacement", DEFAULT_ENABLE_REPLACEMENT);
    if ((!fEnableReplacement) && gArgs.IsArgSet("-mempoolreplacement")) {
        // Minimal effort at forwards compatibility
        std::string strReplacementModeList = gArgs.GetArg("-mempoolreplacement", "");  // default is impossible
        std::vector<std::string> vstrReplacementModes;
        boost::split(vstrReplacementModes, strReplacementModeList, boost::is_any_of(","));
        fEnableReplacement = (std::find(vstrReplacementModes.begin(), vstrReplacementModes.end(), "fee") != vstrReplacementModes.end());
    }

    //（33）-vbparams：帮助文件中的解释为：为指定的版本位部署使用给定的起始/结束时间（仅在私有网络测试时使用）。这个部分的设置
    // 注释为：允许重写版本位参数进行测试。即在私有测试网络中测试软分叉后软件是否正常运行。
    if (gArgs.IsArgSet("-vbparams")) {
        // Allow overriding version bits parameters for testing
        if (!chainparams.MineBlocksOnDemand()) {
            return InitError("Version bits parameters may only be overridden on regtest.");
        }
        for (const std::string& strDeployment : gArgs.GetArgs("-vbparams")) {
            std::vector<std::string> vDeploymentParams;
            boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
            if (vDeploymentParams.size() != 3) {
                return InitError("Version bits parameters malformed, expecting deployment:start:end");
            }
            int64_t nStartTime, nTimeout;
            if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
                return InitError(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
            }
            if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
                return InitError(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
            }
            bool found = false;
            for (int j=0; j<(int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j)
            {
                if (vDeploymentParams[0].compare(VersionBitsDeploymentInfo[j].name) == 0) {
                    UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                    found = true;
                    LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                    break;
                }
            }
            if (!found) {
                return InitError(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
            }
        }
    }
    return true;
    //第三步总结：主要是把这些从外部设置的参数转化为内部变量，即把各种配置文件和终端命令行中的命令参数转变成客户端内部要
    //使用和这些参数相关的变量的值，使客户端按照用户设置的要求（或默认值）运行。
}
//函数主要是确保只有一个比特币进程正在使用数据目录，因为要证数据目录在同一台机器中仅被一个比特币核心核心程序所使用，
//否则如果多个比特币核心程序同时使用同一数据目录，将会造成该程序数据内容产生不一致的情况。
static bool LockDataDirectory(bool probeOnly)
{
    // Make sure only a single Bitcoin process is using the data directory.
    // 首先获取数据目录值，然后打开数据目录下的.lock文件，判断其是否存在。该文件在ubuntu中的$HOME/.bitcoin/文件夹下是存在的，
    // 其内容为空。
    fs::path datadir = GetDataDir();
    //.lock文件的作用是：该文件将通过lock.try_lock()被锁定，但是如果已被其它先启动的比特币程序锁定了的话，本次锁定将失效，
    //同时提示错误信息，并返回false，整个程序将退出。
    if (!LockDirectory(datadir, ".lock", probeOnly)) {
        return InitError(strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running."), datadir.string(), _(PACKAGE_NAME)));
    }
    return true;
}
//该部分是对椭圆曲线密码（ECC）的初始化。选择SHA256准备、随机数生成器准备、椭圆曲线功能开启、验证椭圆曲线开启和重置内存，都是为ECC的正常运行提供的条件
bool AppInitSanityChecks()
{
    // ********************************************************* Step 4: sanity checks 健全性检查

    // Initialize elliptic curve code  初始化椭圆曲线密码（ECC）
    std::string sha256_algo = SHA256AutoDetect();
    LogPrintf("Using the '%s' SHA256 implementation\n", sha256_algo);
    RandomInit();   //初始化RNG-随机数发生器，它是被嵌入到计算机硬件中的随机数生成器，生成的是伪随机数。
    ECC_Start();    //初始化椭圆曲线支持。如果在调用了第一次之后不首先调用ECC_Stop，就不能第二次调用这个函数。
    globalVerifyHandle.reset(new ECCVerifyHandle());

    // Sanity check 健全性检查
    if (!InitSanityCheck())
        return InitError(strprintf(_("Initialization sanity check failed. %s is shutting down."), _(PACKAGE_NAME)));

    // Probe the data directory lock to give an early error message, if possible                     如果可能，探测数据目录锁以提供早期错误消息。
    // We cannot hold the data directory lock here, as the forking for daemon() hasn't yet happened, 我们不能将数据目录锁定在这里，因为deamon()尚未调用forking指令，
    // and a fork will cause weird behavior to it.                                                   并且fork指令将会对它产生一个奇怪的行为。
    return LockDataDirectory(true);
}
//该函数是目录锁检查的主要实现函数，主要是确保只有一个bitcoind运行。这里是再次获取数据目录锁定并一直保持它目录锁锁定状态，直到程序的退出。
bool AppInitLockDataDirectory()
{
    // After daemonization get the data directory lock again and hold on to it until exit                  在守护进程之后，再次获取数据目录锁定并保持它直到退出；
    // This creates a slight window for a race condition to happen, however this condition is harmless: it 这为竞争条件创造了一个小小的窗口，但是这个条件是无害的：它最多会让我们退出而不打印消息给控制台。
    // will at most make us exit without printing a message to console.
    if (!LockDataDirectory(false)) {
        // Detailed error printed inside LockDataDirectory             在LockDataDirectory内部打印详细的错误
        return false;
    }
    return true;
}

bool AppInitMain()
{
    //该部分主要是关于运行网络的选择，如果在启动比特币核心程序时，没有设置相应网络参数，则默认运行主链，否则将根据输入的参数启动相应网络。
    const CChainParams& chainparams = Params(); 
    // ********************************************************* Step 4a: application initialization 第4a步：应用程序初始化
    //这个主要是在非Windows系统中编译的部分，通过CreatePidFile()函数创建进程编号记录文件，该文件名为bitcoind.pid。
#ifndef Win32
    CreatePidFile(GetPidFile(), getpid());
#endif
    //-shrinkdebugfile参数为压缩日志文件。该参数在帮助文件中的解释为：当客户端启动时，对debug.log文件进行压缩处理。默认为1，即在不
    //进行调试时会进行压缩操作。此处的含义为，当启动不使用该参数时会默认执行ShrinkDebugFile()函数，该函数就是具体的调试日志压缩处理
    //过程函数。
    if (gArgs.GetBoolArg("-shrinkdebugfile", logCategories == BCLog::NONE)) {
        // Do this first since it both loads a bunch of debug.log into memory,
        // and because this needs to happen before any other debug.log printing
        ShrinkDebugFile();  //首先这样做，不仅因为它能将一堆debug.log加载到内存中去，而且因为这也需要在任何其他debug.log打印之前发生。
    }

    //因为fPrintToDebugLog变量（定义在util.cpp）默认为true，则程序将用OpenDebugLog()函数正式打开debug.log文件，实现程序运行过程
    //中的记录，方便调试用。
    if (fPrintToDebugLog) {
        if (!OpenDebugLog()) {
            return InitError(strprintf("Could not open debug log file %s", GetDebugLogPath().string()));
        }
    }
    //至此完成了日志文件的打开操作，并完成了预先存储日志信息的输出。

    //fLogTimestamps的定义在util.cpp，默认值为DEFAULT_LOGTIMESTAMPS，而DEFAULT_LOGTIMESTAMPS在util.h中，为true，意味着
    //一般if后的语句不执行，即此处不单独打印“Startup time:（+时间）”这样的时间信息。fLogTimestamps主要是默认在让日志的每一行
    //都带有时间戳信息。
    if (!fLogTimestamps)
        LogPrintf("Startup time: %s\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()));
    LogPrintf("Default data directory %s\n", GetDefaultDataDir().string());
    LogPrintf("Using data directory %s\n", GetDataDir().string());
    LogPrintf("Using config file %s\n", GetConfigFile(gArgs.GetArg("-conf", BITCOIN_CONF_FILENAME)).string());
    LogPrintf("Using at most %i automatic connections (%i file descriptors available)\n", nMaxConnections, nFD);

    // Warn about relative -datadir path.
    if (gArgs.IsArgSet("-datadir") && !fs::path(gArgs.GetArg("-datadir", "")).is_absolute()) {
        LogPrintf("Warning: relative datadir option '%s' specified, which will be interpreted relative to the "
                  "current working directory '%s'. This is fragile, because if bitcoin is started in the future "
                  "from a different location, it will be unable to locate the current data files. There could "
                  "also be data loss if bitcoin is started while in a temporary directory.\n",
            gArgs.GetArg("-datadir", ""), fs::current_path().string());
    }

    InitSignatureCache();       //签名缓存函数
    InitScriptExecutionCache(); //初始化脚本执行缓存函数
    //变量nScriptCheckThreads定义在validation.cpp为0。后面的判断语句为如果该变量不为0，假设为n，则会创建n个线程用来验证脚本。
    LogPrintf("Using %u threads for script verification\n", nScriptCheckThreads);
    if (nScriptCheckThreads) {
        for (int i=0; i<nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&ThreadScriptCheck);
    }

    //整体来看这两段代码就是：创建一个线程，该线程将调用一次scheduler.serviceQueue()决定的serviceLoop函数，并且会重新命名该
    //线程为scheduler。而serviceQueue()函数就是关于任务调度的函数。
    // Start the lightweight task scheduler thread                  启动轻量级任务调度线程
    //代码第一行的效果就是：用boost::bind()函数绑定类的成员函数serviceQueue()和类的对象scheduler，最后的serviceLoop函数对象
    //就可以等效于scheduler.serviceQueue()；
    CScheduler::Function serviceLoop = boost::bind(&CScheduler::serviceQueue, &scheduler);
    //通过线程组对象threadGroup实例化create_thread()函数来创建新的线程，线程的执行函数为boost::bind()函数返回的函数对象。
    threadGroup.create_thread(boost::bind(&TraceThread<CScheduler::Function>, "scheduler", serviceLoop));
    //注册后台处理信号
    GetMainSignals().RegisterBackgroundSignalScheduler(scheduler);
    GetMainSignals().RegisterWithMempoolSignals(mempool);

    /* Register RPC commands regardless of -server setting so they will be
     * available in the GUI RPC console even if external calls are disabled.
     */
    RegisterAllCoreRPCCommands(tableRPC);
#ifdef ENABLE_WALLET
    RegisterWalletRPC(tableRPC);
#endif

    //启动RPCServer、HTTPServer
    /* Start the RPC server already.  It will be started in "warmup" mode    已经启动RPC服务器。 它将以“热身”模式启动进程，而不是已经
     * and not really process calls already (but it will signify connections 真正的进程调用（但它将表示服务器在那里并且稍后准备就绪的连
     * that the server is there and will be ready later).  Warmup mode will  接）。 初始化完成后，热身模式将被禁用。
     * be disabled when initialisation is finished.
     */
    //-server参数解释为：接受命令行和JSON-RPC命令。此处的判断语句为：如果在命令行中有-server命令，就执行下面的语句，如果没有该命令
    //则不执行。
    if (gArgs.GetBoolArg("-server", false))
    {
        //在执行语句中首先给InitMessage信号添加一个新的执行函数SetRPCWarmupStatus，该执行函数的声明在rpc/server.h中
        uiInterface.InitMessage.connect(SetRPCWarmupStatus);
        //然后又会出现一个判断语句，这个判断语句主要涉及到AppInitServers()函数的调用
        if (!AppInitServers())
            return InitError(_("Unable to start HTTP server. See debug log for details."));
    }

    //定义变量nStart
    int64_t nStart;
    //第4a步总结：该步骤为应用程序的初始化：包括启动时创建一个.pid文件来保证只有一个比特币核心程序运行；启动时压缩debug.log文件，
    //打开日志文件，并增加一些调试日志，包括在每行输出内容前加时间戳、数据文件路径、签名和脚本执行的缓存信息等；然后打开脚本验证线
    //程并启动一个轻量级的用来做任务调度的线程；最后注册后台处理信号并启动RPCServer、HTTPServer服务。
    //总之是进一步保证程序的唯一性、完善调试日志内容、开启任务调度线程、启动RPC和HTTP服务等的初始化步骤。
    // ********************************************************* Step 5: verify wallet database integrity 第五步：验证钱包数据库的完整性
    //如果有ENABLE_WALLET宏定义，则执行CWallet::Verify()函数。对于ENABLE_WALLET宏定义在config\bitcoind-config.h中有定义，为1。
    //ENABLE_WALLET定义为1以启用钱包功能
#ifdef ENABLE_WALLET
    if (!VerifyWallets())
        return false;
#endif
    //第五步总结：主要是验证钱包数据库的完整性的，当编译时没有禁用钱包功能（默认开启钱包功能）时会执行这一步，主要由Verify()函数来
    //完成验证工作：包括是否在命令行禁用钱包功能、检查钱包路径、验证钱包环境、恢复私钥、验证钱包的数据库文件等。这个主要是针对钱包的初
    //始化，保证钱包的完整性，方便钱包后面的使用。
    // ********************************************************* Step 6: network initialization 第六步：网络初始化
    // Note that we absolutely cannot open any actual connections 请注意，不到最后面（"start node"时）我们绝对不能打开任何实际的连接
    // until the very end ("start node") as the UTXO/block state  ，因为UTXO/block状态还没有设置好，
    // is not yet setup and may end up being set up twice if we   并且如果在后面需要更新索引，最终可能会使UTXO/block状态设置两次。
    // need to reindex later.
    //断言语句来确保g_connman变量为空，它为空值后又创建了一个CConnman对象，用于设置连接的参数，并把该值赋值给g_connman变量。
    //接着又创建了一个PeerLogicValidation类型的变量，这个类实现的功能是：在产生一个新的区块时，节点是如何处理的。最后用
    //RegisterValidationInterface()函数来注册节点之间的消息处理信号。
    assert(!g_connman);
    g_connman = std::unique_ptr<CConnman>(new CConnman(GetRand(std::numeric_limits<uint64_t>::max()), GetRand(std::numeric_limits<uint64_t>::max())));
    CConnman& connman = *g_connman;

    peerLogic.reset(new PeerLogicValidation(&connman, scheduler));
    RegisterValidationInterface(peerLogic.get());

    // sanitize comments per BIP-0014, format user agent and check total size 根据BIP-0014清理注释，格式化用户代理并检查总大小
    std::vector<std::string> uacomments;
    //for循环的判断体中有个命令参数-uacomment，在帮助文件中对该命令的注释为：将注释附加到用户代理字符串中。
    for (const std::string& cmt : gArgs.GetArgs("-uacomment")) {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            return InitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(cmt);
    }

    //首先将用户对代理的注释信息保存到uacomments中，将CLIENT_NAME、CLIENT_VERSION和uacomments
    //按照/CLIENT_NAME:CLIENT_VERSION(comments1;comments2;...)/的格式连接起来，最后判断格式化后的字符串是否超过了最大长度
    //限制256，如果超过了报错；没超过继续下面的内容。
    strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments);
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH) {
        return InitError(strprintf(_("Total length of network version string (%i) exceeds maximum length (%i). Reduce the number or size of uacomments."),
            strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    //接下来是关于设定网络范围的代码
    //首先if语句判断是否有-onlynet参数，该参数在帮助文件中的解释为：只连接特定网络中的节点，取值有ipv4、ipv6和onion三种。
    if (gArgs.IsArgSet("-onlynet")) {
        std::set<enum Network> nets;
        for (const std::string& snet : gArgs.GetArgs("-onlynet")) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
            nets.insert(net);
        }
        for (int n = 0; n < NET_MAX; n++) {
            enum Network net = (enum Network)n;
            if (!nets.count(net))
                SetLimited(net);
        }
    }

    //关于代理设置的一段代码
    // Check for host lookup allowed before parsing any network related parameters 在解析任何网络相关参数之前检查主机查找。
    //①-dns：允许进行dns解析，默认为1；②-proxyrandomize：为每个代理连接都随机颁发一个证书，默认为1；③-proxy：为网络所有的通信设置
    //一个代理，默认为空。在这部分，首先检查上面的三个参数，然后会通过SetLimited(NET_TOR);来禁用洋葱路由。然后检查，如果-proxy不为空
    //且值不为0，那么根据代理域名进行dns查询，查到相应的ip并检查代理的合法性之后，再为IPV4、IPV6以及TOR设置代理。最后禁用TOR。
    //设置洋葱路由的代码
    fNameLookup = gArgs.GetBoolArg("-dns", DEFAULT_NAME_LOOKUP);

    bool proxyRandomize = gArgs.GetBoolArg("-proxyrandomize", DEFAULT_PROXYRANDOMIZE);
    // -proxy sets a proxy for all outgoing network traffic                                                   -proxy为所有出站网络流量设置一个代理。
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default -noproxy (or -proxy=0) 以及空字符串可以用来不设置代理，这是默认值。
    std::string proxyArg = gArgs.GetArg("-proxy", "");
    SetLimited(NET_TOR);
    if (proxyArg != "" && proxyArg != "0") {
        CService proxyAddr;
        if (!Lookup(proxyArg.c_str(), proxyAddr, 9050, fNameLookup)) {
            return InitError(strprintf(_("Invalid -proxy address or hostname: '%s'"), proxyArg));
        }

        proxyType addrProxy = proxyType(proxyAddr, proxyRandomize);
        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address or hostname: '%s'"), proxyArg));

        SetProxy(NET_IPV4, addrProxy);
        SetProxy(NET_IPV6, addrProxy);
        SetProxy(NET_TOR, addrProxy);
        SetNameProxy(addrProxy);
        SetLimited(NET_TOR, false); // by default, -proxy sets onion as reachable, unless -noonion later    //默认情况下，-proxy将洋葱设置为可访问，除非稍后使用-noonion
    }

    // -onion can be used to set only a proxy for .onion, or override normal proxy for .onion addresses                 -onion可以用来设置.onion的代理，或者覆盖.onion地址的普通代理
    // -noonion (or -onion=0) disables connecting to .onion entirely                                                    -noonion (或者-onion=0)是完全禁止连接到.onion
    // An empty string is used to not override the onion proxy (in which case it defaults to -proxy set above, or none) 一个空字符串用于不覆盖洋葱代理（在这种情况下，它默认-proxy为设置上面，或不设置）。
    std::string onionArg = gArgs.GetArg("-onion", "");
    if (onionArg != "") {
        if (onionArg == "0") { // Handle -noonion/-onion=0        // 当-noonion/-onion=0的情况
            SetLimited(NET_TOR); // set onions as unreachable     // 禁用洋葱路由
        } else {
            CService onionProxy;
            if (!Lookup(onionArg.c_str(), onionProxy, 9050, fNameLookup)) {
                return InitError(strprintf(_("Invalid -onion address or hostname: '%s'"), onionArg));
            }
            proxyType addrOnion = proxyType(onionProxy, proxyRandomize);
            if (!addrOnion.IsValid())
                return InitError(strprintf(_("Invalid -onion address or hostname: '%s'"), onionArg));
            SetProxy(NET_TOR, addrOnion);
            SetLimited(NET_TOR, false);
        }
    }
    //这段代码主要是：如果-onion 参数不为空，且值不为0，则会解析该代理域名，然后启动洋葱路由。

    // see Step 2: parameter interactions for more information about these
    //-listen：这个参数在帮助文件中的解释为：接受来自外部的连接（如果没有设置-proxy或-connect，默认1）。当时使用这个参数的目
    //的是：当-listen参数为0时-bind或-whitebind不能被设置。现在这个参数在此处使用主要是：把该参数的值赋值给fListen变量。
    fListen = gArgs.GetBoolArg("-listen", DEFAULT_LISTEN);
    //-discover：这个参数在帮助文件中的解释为：发现自己的IP地址（侦听打开（-listen = true）并且没有设置-externalip或-proxy时
    //默认为1）。
    fDiscover = gArgs.GetBoolArg("-discover", true);
    //-blocksonly：这个参数在帮助文件中的解释为：是否只以区块模式运行？默认为false。当时使用这个参数的目的是：在钱包参数交互中，
    //这个参数和-walletbroadcast参数是不能同时设置为true的。此处用此参数主要是：把该参数的相反值赋值给fRelayTxes变量。
    fRelayTxes = !gArgs.GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY);
    //可以知道这三个赋值语句主要是把一些和网络连接有关的外部参数赋值给内部变量，方便后面真正的网络连接使用的。

    //下面是一个for循环语句，这个语句是关于把输入ip指定为公有的ip地址的
    //该段代码中涉及到一个参数：-externalip，这个参数在帮助文件中的解释为：指定您自己的公共地址，参数后面跟着的是IP地址。
    for (const std::string& strAddr : gArgs.GetArgs("-externalip")) {
        CService addrLocal;
        if (Lookup(strAddr.c_str(), addrLocal, GetListenPort(), fNameLookup) && addrLocal.IsValid())
            AddLocal(addrLocal, LOCAL_MANUAL);
        else
            return InitError(ResolveErrMsg("externalip", strAddr));
    }

    //接下来会有一段条件编译，这是关于是否启用ZMQ的(ZMQ的详细讲解可参考：https://www.cnblogs.com/rainbowzc/p/3357594.html)
    //在此条件编译中判断的是ENABLE_ZMQ宏定义，这个宏定义来表示是否启用ZMQ。ZMQ封装了网络通信、消息队列、线程调度等功能，向上层提供
    //简洁的API，应用程序通过加载库文件，调用API函数来实现高性能网络通信。
#if ENABLE_ZMQ
    //若定义该宏，就会用CZMQNotificationInterface::Create()函数开启ZMQ，并用RegisterValidationInterface()函数注册区块处理的信号。
    pzmqNotificationInterface = CZMQNotificationInterface::Create();
    if (pzmqNotificationInterface) {
        RegisterValidationInterface(pzmqNotificationInterface);
    }
#endif
    //最后会有一段关于设置最大上传速度的代码
    uint64_t nMaxOutboundLimit = 0; //unlimited unless -maxuploadtarget is set 除非设置了-maxuploadtarget，要不是就无限制
    uint64_t nMaxOutboundTimeframe = MAX_UPLOAD_TIMEFRAME;
    //-maxuploadtarget参数在帮助文件中的解释为：保持上传流量在给定的值之下，值为0表示无限制，默认为0。可以知道这个参数是用来设置
    //最大的上传速度的，默认值时该上传速度是无限制的。
    if (gArgs.IsArgSet("-maxuploadtarget")) {
        nMaxOutboundLimit = gArgs.GetArg("-maxuploadtarget", DEFAULT_MAX_UPLOAD_TARGET)*1024*1024;
    }
    //第六步总结：主要是对网络的初始化，是进行一些网络参数的设置，而不是真正的网络连接。在这一步中包括了给用户代理添加注释、设定网络
    //范围、代理设置、设置洋葱路由、把一些必要的外部参数赋值给内部变量来为以后的网络服务准备、把输入ip指定为公有的ip地址、是否启用ZMQ、
    //设置最大上传速度等操作。
    // ********************************************************* Step 7: load block chain 第七步：加载区块链数据

    fReindex = gArgs.GetBoolArg("-reindex", false);
    bool fReindexChainState = gArgs.GetBoolArg("-reindex-chainstate", false);

    // cache size calculations
    int64_t nTotalCache = (gArgs.GetArg("-dbcache", nDefaultDbCache) << 20);
    nTotalCache = std::max(nTotalCache, nMinDbCache << 20); // total cache cannot be less than nMinDbCache    //总缓存不能小于nMinDbCache
    nTotalCache = std::min(nTotalCache, nMaxDbCache << 20); // total cache cannot be greater than nMaxDbcache //总缓存不能大于nMaxDbcache
    int64_t nBlockTreeDBCache = nTotalCache / 8;
    nBlockTreeDBCache = std::min(nBlockTreeDBCache, (gArgs.GetBoolArg("-txindex", DEFAULT_TXINDEX) ? nMaxBlockDBAndTxIndexCache : nMaxBlockDBCache) << 20);
    nTotalCache -= nBlockTreeDBCache;
    int64_t nCoinDBCache = std::min(nTotalCache / 2, (nTotalCache / 4) + (1 << 23)); // use 25%-50% of the remainder for disk cache // 剩余的25％-50％用于磁盘缓存
    nCoinDBCache = std::min(nCoinDBCache, nMaxCoinsDBCache << 20); // cap total coins db cache                  //总计比特币数据库缓存
    nTotalCache -= nCoinDBCache;
    nCoinCacheUsage = nTotalCache; // the rest goes to in-memory cache                  //其余的则进入内存缓存
    int64_t nMempoolSizeMax = gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    LogPrintf("Cache configuration:\n");
    LogPrintf("* Using %.1fMiB for block index database\n", nBlockTreeDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for chain state database\n", nCoinDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for in-memory UTXO set (plus up to %.1fMiB of unused mempool space)\n", nCoinCacheUsage * (1.0 / 1024 / 1024), nMempoolSizeMax * (1.0 / 1024 / 1024));
    //由这部分的注释也可以知道，这段代码与缓存大小的计算有关。由注释内容还知道一些具体信息：① 4MB≤总缓存≤16384MB。② 块索引数据库缓存
    //大小与-txindex参数和-dbcache参数有关。③ 链状态数据库大小与-dbcache参数有关。④交易内存池缓存大小设置与-dbcache参数和-maxmempool
    //参数有关。
    //①-reindex：该参数在帮助文件中的解释为：从磁盘上的blk*.dat文件重建链状态和块索引。此处该参数的作用是：如果该参数没有设置成true
    //则fReindex 变量值为false。②-reindex-chainstate：该参数在帮助文件中的解释为：从当前索引块重建链状态。处该参数的作用是：如果该
    //参数没有设置成true则fReindexChainState 变量值为false。③-dbcache：该参数在帮助文件中的解释为：以兆字节为单位设置数据库缓存大
    //小。默认大小为450.④-txindex：该参数在帮助文件中的解释为：维护完整的交易索引，主要是被getrawtransaction这个rpc调用来使用，默
    //认不启用。⑤-maxmempool：该参数在帮助文件中的解释为：设置交易内存池的最大大小，单位为MB，默认值为300。
    //总结这部分的实现逻辑为：首先从命令行中获取两个参数，-reindex和-reindex-chainstate，这两个重索引默认都是不启用。接下来开始计算
    //缓存的大小，首先是总的缓存大小用nTotalCache表示，通过-dbcache参数设置，然后这个值要取在nMinDbCache和nMaxDbCache之间。接下来
    //计算nBlockTreeDBCache和nCoinDBCache以及nCoinCacheUsage，并且
    //nTotalCache = nBlockTreeDBCache + nCoinDBCache + nCoinCacheUsage。
    
    //关于加载区块索引的代码
    //首先设置了一个标记变量fLoaded表示索引加载是否成功，如果执行完循环体发现此变量还是false并且没有请求关闭程序的话，那么就再执行一遍。
    bool fLoaded = false;
    while (!fLoaded && !fRequestShutdown) {
        bool fReset = fReindex;
        std::string strLoadError;

        uiInterface.InitMessage(_("Loading block index..."));

        nStart = GetTimeMillis();
        do {
            try {
                //在循环体中首先出现了一个UnloadBlockIndex()函数。由于此循环体可能不止执行一遍，所以先调用UnloadBlockIndex()来
                //清除上次循环可能设置的一些变量，这个函数的实现在validation.cpp。
                UnloadBlockIndex();
                pcoinsTip.reset();
                pcoinsdbview.reset();
                pcoinscatcher.reset();
                // new CBlockTreeDB tries to delete the existing file, which
                // fails if it's still open from the previous loop. Close it first:
                //修剪模式重索引时擦除不可用的块文件和所有的撤销数据文件：创建一个CBlockTreeDB类，这个类是用来向/blocks/index/*下面的文件
                //进行读写操作。然后判断fReset是否为true，这个变量也就是-reindex参数用来设定是否重新创建所有的索引，如果为true，那么就调用
                //CBlockTreeDB中的WriteReindexing()函数向数据库中写入数据。接下来出现的fPruneMode变量是由-prune区块裁剪参数决定的一个变量；
                //它是用来修剪已确认的区块的。在这里主要是如果裁剪模式fPruneMode为true，则需要对区块重新索引，此时会调用CleanupBlockRevFiles()
                //函数擦除不可用的块文件和所有的撤销数据文件。
                pblocktree.reset();
                pblocktree.reset(new CBlockTreeDB(nBlockTreeDBCache, false, fReset));

                if (fReset) {
                    pblocktree->WriteReindexing(true);
                    //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
                    //如果我们在修剪模式下重新索引，那么擦除不可用的块文件和所有的撤销数据文件
                    //CleanupBlockRevFiles()函数在init.cpp。对它的注释为：如果将-reindex和-prune一起用，那么就将重索引时不考虑的
                    //一些区块文件直接删除。因为重索引是从0号区块一直连续的读取，直到某一个区块信息缺失就停止读取，缺失的区块之后所有
                    //的区块都会被直接删除。同时还需要删除rev文件，因为这些文件在重索引时会重新生成。根据注释的内容来看，这个函数要做
                    //的就是删除某个缺失的区块之后所有的区块数据，以及rev开头的文件。接下来先将所有的文件和对应的路径保存到一个map中，
                    //然后用一个变量nContigCounter从0开始计数，直到遇到第一个不一致的文件名，就从这个开始删除。
                    if (fPruneMode)
                        CleanupBlockRevFiles();
                }

                if (fRequestShutdown) break;

                // LoadBlockIndex will load fTxIndex from the db, or set it if    LoadBlockIndex首先将从数据库中加载fTxIndex变量，如果是在进行重索引那么就从命令行读取fTxIndex的值。
                // we're reindexing. It will also load fHavePruned if we've       另外如果我们之前删除过区块文件，那么这里还会加载fHavePruned变量。
                // ever removed a block file from disk.
                // Note that it also sets fReindex based on the disk flag!        同时还会根据磁盘上的标记来设置fReindex变量，
                // From here on out fReindex and fReset mean something different! 并且从此往后fReindex和fReset就表示不同的含义。
                //关于LoadBlockIndex()函数的一个判断语句，其中LoadBlockIndex()函数在validation.cpp中，这个函数的实现逻辑是：
                //函数的输入参数chainparams是根据三个不同网络之一的对应的不同的写好了的参数；然后检查fReindex变量，如果设置了这
                //个变量，那么之后会进行重新索引，这里也就没有必要先加载索引了；如果没有设置fReindex，那么这里就是首次加载也是唯
                //一的加载索引的地方。所谓加载索引，就是将/blocks/index/*中的文件加载到内存，实现时就是通过LoadBlockIndexDB()函
                //数并将结果保存在变量mapBlockIndex中，如果加载成功，那么mapBlockIndex就不为空，needs_init也就为false。
                if (!LoadBlockIndex(chainparams)) {
                    strLoadError = _("Error loading block database");
                    break;
                }

                // 接下来是一段关于区块合法性检测的代码
                // If the loaded chain has a wrong genesis, bail out immediately    如果加载的链中有个错误的创世块，那么立即修复它
                // (we're likely using a testnet datadir, or the other way around). (可能使用测试网络的数据目录，或者周围的其他的路径)
                //判断如果mapBlockIndex中没有加载创世区块，或者存在错误的创世区块，则会提示：不正确或者没有创世区块。是网络的数据目录错误了吗？
                if (!mapBlockIndex.empty() && mapBlockIndex.count(chainparams.GetConsensus().hashGenesisBlock) == 0)
                    return InitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));

                // Check for changed -txindex state                                 检查-txindex状态
                // 检查-txindex参数的值是否和fTxIndex变量相等，如果不等，则提示：“您需要使用-reindex重建数据库以更改-txindex”，并跳出循环。
                if (fTxIndex != gArgs.GetBoolArg("-txindex", DEFAULT_TXINDEX)) {
                    strLoadError = _("You need to rebuild the database using -reindex to change -txindex");
                    break;
                }

                // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
                // in the past, but is now trying to run unpruned.    检查-prune的状态。因为用户可能会手动删除一些文件，然后现在又想在未剪裁模式下运行
                //如果用户已经手动修剪了区块文件，然后又想开启不修剪区块模式，则会提示：“您需要使用-reindex重建数据库以回到未修剪模式。 这将重新下载整个区块链”，并跳出循环。
                if (fHavePruned && !fPruneMode) {
                    strLoadError = _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain");
                    break;
                }

                // At this point blocktree args are consistent with what's on disk.  此时，blocktree上的参数和磁盘上的一致。
                // If we're not mid-reindex (based on disk + args), add a genesis block on disk  如果我们不是mid-reindex（基于在磁盘和参数），那么在磁盘上添加一个创世区块（否则使用已经在磁盘上的参数）。
                // (otherwise we use the one already on disk).                       在重新索引完成后，这将在ThreadImport中再次调用。
                // This is called again in ThreadImport after the reindex completes.
                //函数LoadGenesisBlock()的声明在validation.h
                if (!fReindex && !LoadGenesisBlock(chainparams)) {
                    strLoadError = _("Error initializing block database");
                    break;
                }

                // At this point we're either in reindex or we've loaded a useful
                // block tree into mapBlockIndex! 此时要么重新索引，要么加载一个有用的区块树到mapBlockIndex中!

                //有两个变量：pcoinsdbview 和pcoinscatcher。pcoinsdbview变量主要是初始化一个CoinsViewDB，它配备了从LevelDB中
                //加载比特币的方法。pcoinscatcher变量是一个错误捕捉器，它是一个可以忽略的小程序。
                pcoinsdbview.reset(new CCoinsViewDB(nCoinDBCache, false, fReset || fReindexChainState));
                pcoinscatcher.reset(new CCoinsViewErrorCatcher(pcoinsdbview.get()));

                // If necessary, upgrade from older database format.                                  如有必要，从旧数据库格式升级。
                // This is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate 如果用-reindex或-reindex-chainstate清除了coinviewdb，升级是一个无操作。
                //判断调用的Upgrade()函数，这个函数的作用是：尝试从较旧的数据库格式进行更新。 返回是否发生错误的bool值。
                if (!pcoinsdbview->Upgrade()) {
                    strLoadError = _("Error upgrading chainstate database");
                    break;
                }

                // ReplayBlocks is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
                //如果用-reindex或-reindex-chainstate清除了coinviewdb，ReplayBlocks是一个无操作。
                //接着判断调用的ReplayBlocks()函数，该函数的作用是：没有完全应用于数据库的重放块
                if (!ReplayBlocks(chainparams, pcoinsdbview.get())) {
                    strLoadError = _("Unable to replay blocks. You will need to rebuild the database using -reindex-chainstate.");
                    break;
                }

                // The on-disk coinsdb is now in a good state, create the cache
                //磁盘上的coinsdb现在处于良好的状态，那么就创建缓存。
                //pcoinsTip变量是关于区块链缓存的，它是代表活动链状态的高速缓存，并由数据库视图支持。
                pcoinsTip.reset(new CCoinsViewCache(pcoinscatcher.get()));
                //赋值变量：is_coinsview_empty，然后判断该变量。这里主要是如果fReset、 fReindexChainState和GetBestBlock().IsNull()都为false时，
                //会出现一个断言语句；如果不仅如此，LoadChainTip()函数返回的值也为false，那么会提示：初始化区块数据库错误。其中LoadChainTip()函数
                //的作用是：根据数据库信息更新链末端。
                bool is_coinsview_empty = fReset || fReindexChainState || pcoinsTip->GetBestBlock().IsNull();
                if (!is_coinsview_empty) {
                    // LoadChainTip sets chainActive based on pcoinsTip's best block 
                    // LoadChainTip根据pcoinsTip的最佳模块设置chainActive。
                    if (!LoadChainTip(chainparams)) {
                        strLoadError = _("Error initializing block database");
                        break;
                    }
                    assert(chainActive.Tip() != nullptr);
                }
                //倒退链状态的操作：首先判断fReset变量，如果为false，则调用RewindBlockIndex()函数开始回退数据库到预分叉状态，
                //如果回退失败，则报错，并跳出循环。RewindBlockIndex()函数主要功能是：当数据缺失的活动链中存在块时，倒退链状态
                //并将其从块索引中移除。
                if (!fReset) {
                    // Note that RewindBlockIndex MUST run even if we're about to -reindex-chainstate. 请注意，即使我们即将关注-reindex-chainstate，RewindBlockIndex也必须运行。
                    // It both disconnects blocks based on chainActive, and drops block data in        它根据chainActive断开区块，并根据缺少可见的数据将区块数据放到mapBlockIndex中。
                    // mapBlockIndex based on lack of available witness data.
                    uiInterface.InitMessage(_("Rewinding blocks..."));
                    if (!RewindBlockIndex(chainparams)) {
                        strLoadError = _("Unable to rewind the database to a pre-fork state. You will need to redownload the blockchain");
                        break;
                    }
                }
                //验证区块的操作：判断还是is_coinsview_empty变量，如果为false，则开始验证区块：包括对修剪后的数据块长度的验证、区块
                //时间的验证和区块的健全性检查。
                if (!is_coinsview_empty) {
                    uiInterface.InitMessage(_("Verifying blocks..."));
                    if (fHavePruned && gArgs.GetArg("-checkblocks", DEFAULT_CHECKBLOCKS) > MIN_BLOCKS_TO_KEEP) {
                        LogPrintf("Prune: pruned datadir may not have more than %d blocks; only checking available blocks",
                            MIN_BLOCKS_TO_KEEP);
                    }

                    {
                        LOCK(cs_main);
                        CBlockIndex* tip = chainActive.Tip();
                        RPCNotifyBlockChange(true, tip);
                        if (tip && tip->nTime > GetAdjustedTime() + 2 * 60 * 60) {
                            strLoadError = _("The block database contains a block which appears to be from the future. "
                                    "This may be due to your computer's date and time being set incorrectly. "
                                    "Only rebuild the block database if you are sure that your computer's date and time are correct");
                            break;
                        }
                    }

                    if (!CVerifyDB().VerifyDB(chainparams, pcoinsdbview.get(), gArgs.GetArg("-checklevel", DEFAULT_CHECKLEVEL),
                                  gArgs.GetArg("-checkblocks", DEFAULT_CHECKBLOCKS))) {
                        strLoadError = _("Corrupted block database detected");
                        break;
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s\n", e.what());
                strLoadError = _("Error opening block database");
                break;
            }

            fLoaded = true;
        } while(false);

        //如果fLoaded和fRequestShutdown还是都为false，则首先建议重新索引：如果fReset为false，则调用ThreadSafeQuestion()函数。
        //如果该函数后返回的值为true，则把fReindex变量改为true，fRequestShutdown变量改为false；否则打印日志内容：“中止块数据库
        //重建。退出”。如果fReset为true，返回初始化错误。
        if (!fLoaded && !fRequestShutdown) {
            // first suggest a reindex                  首先建议重新索引
            if (!fReset) {
                bool fRet = uiInterface.ThreadSafeQuestion(
                    strLoadError + ".\n\n" + _("Do you want to rebuild the block database now?"),
                    strLoadError + ".\nPlease restart with -reindex or -reindex-chainstate to recover.",
                    "", CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT);
                if (fRet) {
                    fReindex = true;
                    fRequestShutdown = false;
                } else {
                    LogPrintf("Aborted block database rebuild. Exiting.\n");
                    return false;
                }
            } else {
                return InitError(strLoadError);
            }
        }
    }

    //在上面的while循环中的判断语句是fLoaded和fRequestShutdown都为false，那么下面的一段代码就是当他们不为false时执行的语句
    // As LoadBlockIndex can take several minutes, it's possible the user        由于LoadBlockIndex可能需要几分钟时间，因此用户可能会在上次操作期间请求终止GUI。
    // requested to kill the GUI during the last operation. If so, exit.         如果是这样，退出。
    // As the program has not fully started yet, Shutdown() is possibly overkill.由于程序尚未完全启动，Shutdown（）可能是误杀的。
    if (fRequestShutdown)
    {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }
    if (fLoaded) {
        LogPrintf(" block index %15dms\n", GetTimeMillis() - nStart);
    }
    //创建fee_estimates.dat文件
    fs::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
    CAutoFile est_filein(fsbridge::fopen(est_path, "rb"), SER_DISK, CLIENT_VERSION);
    // Allowed to fail as this file IS missing on first startup.                允许失败，因为该文件在第一次启动时丢失。
    if (!est_filein.IsNull())
        ::feeEstimator.Read(est_filein);
    fFeeEstimatesInitialized = true;
    //由该文件名可以知道是关于费用估算的。该文件保存的是在程序关闭之前的估算费用和优先级的统计信息，这些信息会在启动程序时读入。
    //第七步总结：主要是关于加载区块链数据的，该数据保存在$HOME/.bitcoin目录下。首先计算区块的缓存大小；然后设置加载区块索引；
    //接着进行区块合法性检测；再是区块数据的一系列的操作，包括数据库格式的更新、重放块检测、倒退链状态、验证区块等操作；最后是创
    //建fee_estimates.dat文件保存费用于估算和优先级的统计信息。其中也涉及到一些日志打印和故障信息。
    // ********************************************************* Step 8: load wallet  第八步：加载钱包
#ifdef ENABLE_WALLET
    if (!OpenWallets())
        return false;
#else
    LogPrintf("No wallet support compiled in!\n");
#endif
    //第八步总结：就是用一个条件编译语句，判断如果启动钱包功能，则加载钱包。
    // ********************************************************* Step 9: data directory maintenance 第九步：数据目录维护

    // if pruning, unset the service bit and perform the initial blockstore prune 如果打开了修剪模式，则在任何钱包重新扫描后，
    // after any wallet rescanning has taken place.                               不设置NODE_NETWORK并执行初始区块存储的修剪。
    //修剪区块存储数据:判断条件是：是否打开了修剪模式（由fPruneMode的值确定）？在打开了修剪模式的情况下，在日志文件中
    //输出“在修剪模式下不设置NODE_NETWORK”日志；然后判断是否重建链状态和块索引（由fReindex的值确定）？如果没有重索引，
    //则会进行区块存储的修剪。修剪功能由PruneAndFlush()函数实现，该函数声明在validation.h，实现在validation.cpp，这
    //个函数主要是修剪区块文件并刷新状态到磁盘。
    if (fPruneMode) {
        LogPrintf("Unsetting NODE_NETWORK on prune mode\n");
        nLocalServices = ServiceFlags(nLocalServices & ~NODE_NETWORK);
        if (!fReindex) {
            uiInterface.InitMessage(_("Pruning blockstore..."));
            PruneAndFlush();
        }
    }
    //区块隔离见证的部署:第二个if判断语句中两个赋值语句，主要都是关于隔离见证部署问题的
    if (chainparams.GetConsensus().vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0) {
        // Only advertise witness capabilities if they have a reasonable start time.         只有在有合理的开始时间的情况下才告知具有隔离见证的权利。
        // This allows us to have the code merged without a defined softfork, by setting its 这允许我们通过将代码结束时间设置为0来合并没有定义的软分叉的代码。
        // end time to 0.
        // Note that setting NODE_WITNESS is never required: the only downside from not      请注意，不需要设置NODE_WITNESS：
        // doing so is that after activation, no upgraded nodes will fetch from you.         不设置它的唯一的缺点是，在激活之后，没有升级的节点将会从你那里获取。
        nLocalServices = ServiceFlags(nLocalServices | NODE_WITNESS);
    }
    //第九步总结：这个部分是关于数据目录的维护的，牵涉到比特币的区块数据结构：修剪区块存储数据和隔离见证在区块中的部署。
    //其中此版本的比特币核心是默认使用隔离见证的。
    // ********************************************************* Step 10: import blocks 第十步：导入数据块

    //检查磁盘可用空间:这是由CheckDiskSpace()函数检查，该函数的声明在validation.h，实现在validation.cpp，该函数的作用是：
    //检查磁盘可用空间，如果空闲空间小于nMinDiskSpace（默认为50MB），则会报错。
    if (!CheckDiskSpace())
        return false;

    // Either install a handler to notify us when genesis activates, or set fHaveGenesis directly. 要么安装处理程序当同源链激活新区块的时候通知我们，要么直接设置fHaveGenesis为true。
    // No locking, as this happens before any background thread is started.                        没有锁定，因为这发生在任何后台线程开始之前。
    //通知激活的新区块:这是个if-else语句，判断条件是：Tip()函数返回的该链的激活块的索引，如果是一个空指针，则表示该区块没有被
    //同步，会连接到BlockNotifyGenesisWait；否则fHaveGenesis直接设置成true。
    if (chainActive.Tip() == nullptr) {
        uiInterface.NotifyBlockTip.connect(BlockNotifyGenesisWait);
    } else {
        fHaveGenesis = true;
    }
    //最佳块改变时的操作:此时会有一个参数的设置值的判断，该参数是：-blocknotify，该参数在帮助文件中的解释是：当最佳区块改变时执行
    //命令。如果最佳区块被更改，则连接回叫区块通知BlockNotifyCallback函数。
    if (gArgs.IsArgSet("-blocknotify"))
        uiInterface.NotifyBlockTip.connect(BlockNotifyCallback);

    //从外部导入区块数据:这在一个for循环中进行，由参数-loadblock的文件中依次导入区块数据到vector类容器变量vImportFiles中。然后
    //创建一个线程用来捆绑该容器。-loadblock参数在帮助文件中的解释为：在启动时从外部blk000???.dat文件导入块，即导入的块数据在外
    //部的blk000???.dat样式的文件中。
    std::vector<fs::path> vImportFiles;
    for (const std::string& strFile : gArgs.GetArgs("-loadblock")) {
        vImportFiles.push_back(strFile);
    }

    threadGroup.create_thread(boost::bind(&ThreadImport, vImportFiles));

    // Wait for genesis block to be processed 等待生成块被处理
    //等待处理生成块:当有需要处理的生成块时（fHaveGenesis = false），使通知处于等待状态。当处理完生成块后断开
    //BlockNotifyGenesisWait的连接。
    {
        WaitableLock lock(cs_GenesisWait);
        // We previously could hang here if StartShutdown() is called prior to
        // ThreadImport getting started, so instead we just wait on a timer to
        // check ShutdownRequested() regularly.
        while (!fHaveGenesis && !ShutdownRequested()) {
            condvar_GenesisWait.wait_for(lock, std::chrono::milliseconds(500));
        }
        uiInterface.NotifyBlockTip.disconnect(BlockNotifyGenesisWait);
    }

    if (ShutdownRequested()) {
        return false;
    }
    //第十步总结：此部分是节点导入数据块，使区块更新最新认证区块。首先会检查磁盘空间是否可容下新数据块；然后收到有新区块产生的通知；
    //当最佳区块受到攻击改变时会有回叫通知的操作；然后从外部导入新的数据块；当有生成块需要处理时，会使通知处于等待状态，直到处理完，
    //然后断开通知的连接。
    // ********************************************************* Step 11: start node 第十一步：启动节点服务

    int chain_active_height;

    //// debug print                调试日志打印
    //打印调试日志:开始会打印两个调试日志，在日志文件中打印块索引映射的元素个数（mapBlockIndex.size）和活动链的区块高度（nBestHeight）。
    {
        LOCK(cs_main);
        LogPrintf("mapBlockIndex.size() = %u\n", mapBlockIndex.size());
        chain_active_height = chainActive.Height();
    }
    LogPrintf("nBestHeight = %d\n", chain_active_height);
    //自动创建Tor隐藏服务:上面的代码表示读取是否有设置-listenonion，如果有设置则执行StartTorControl()函数，该函数是与Tor沟通的
    //功能中的启动Tor控制的函数；Tor是第二代洋葱路由(onion routing)的一种实现，用户通过Tor可以在因特网上进行匿名交流。如果没有设
    //置-listenonion参数，则默认不打开该功能，则不执行StartTorControl()函数。
    if (gArgs.GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION))
        StartTorControl(threadGroup, scheduler);
    //发现线程:该段代码主要是Discover()发现线程函数，该函数在这里面主要是发现与本地节点相连接的其他节点。
    Discover(threadGroup);

    // Map ports with UPnP 使用UPnP映射端口
    //映射upnp设备:该部分就是检测-upnp参数，如果有设置会用MapPort()来映射upnp设备。UPnP是各种各样的智能设备、无线设备和个人电脑等
    //实现遍布全球的对等网络的结构。
    MapPort(gArgs.GetBoolArg("-upnp", DEFAULT_UPNP));

    //初始化connOptions对象，以启动节点服务:connOptions是CConnman类中Options结构体对象（CConnman类在net.h的119行）。
    CConnman::Options connOptions;
    connOptions.nLocalServices = nLocalServices;
    connOptions.nMaxConnections = nMaxConnections;
    connOptions.nMaxOutbound = std::min(MAX_OUTBOUND_CONNECTIONS, connOptions.nMaxConnections);
    connOptions.nMaxAddnode = MAX_ADDNODE_CONNECTIONS;
    connOptions.nMaxFeeler = 1;
    connOptions.nBestHeight = chain_active_height;
    connOptions.uiInterface = &uiInterface;
    connOptions.m_msgproc = peerLogic.get();
    connOptions.nSendBufferMaxSize = 1000*gArgs.GetArg("-maxsendbuffer", DEFAULT_MAXSENDBUFFER);
    connOptions.nReceiveFloodSize = 1000*gArgs.GetArg("-maxreceivebuffer", DEFAULT_MAXRECEIVEBUFFER);
    connOptions.m_added_nodes = gArgs.GetArgs("-addnode");

    connOptions.nMaxOutboundTimeframe = nMaxOutboundTimeframe;
    connOptions.nMaxOutboundLimit = nMaxOutboundLimit;

    for (const std::string& strBind : gArgs.GetArgs("-bind")) {
        CService addrBind;
        if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false)) {
            return InitError(ResolveErrMsg("bind", strBind));
        }
        connOptions.vBinds.push_back(addrBind);
    }
    for (const std::string& strBind : gArgs.GetArgs("-whitebind")) {
        CService addrBind;
        if (!Lookup(strBind.c_str(), addrBind, 0, false)) {
            return InitError(ResolveErrMsg("whitebind", strBind));
        }
        if (addrBind.GetPort() == 0) {
            return InitError(strprintf(_("Need to specify a port with -whitebind: '%s'"), strBind));
        }
        connOptions.vWhiteBinds.push_back(addrBind);
    }

    for (const auto& net : gArgs.GetArgs("-whitelist")) {
        CSubNet subnet;
        LookupSubNet(net.c_str(), subnet);
        if (!subnet.IsValid())
            return InitError(strprintf(_("Invalid netmask specified in -whitelist: '%s'"), net));
        connOptions.vWhitelistedRange.push_back(subnet);
    }

    connOptions.vSeedNodes = gArgs.GetArgs("-seednode");

    // Initiate outbound connections unless connect=0
    connOptions.m_use_addrman_outgoing = !gArgs.IsArgSet("-connect");
    if (!connOptions.m_use_addrman_outgoing) {
        const auto connect = gArgs.GetArgs("-connect");
        if (connect.size() != 1 || connect[0] != "0") {
            connOptions.m_specified_outgoing = connect;
        }
    }
    if (!connman.Start(scheduler, connOptions)) {
        return false;
    }
    //第十一步总结：该部分是启动节点服务阶段，也是真正的网络连接完成阶段。在该部分开始前会打印两个调试日志，分别是索引映射
    //的元素个数和活动链的区块高度；然后是创建Tor隐藏服务、发现与本地节点相连接的其他节点、映射upnp设备；最后是管理网络连
    //接选项参数的设定。
    // ********************************************************* Step 12: finished 第十二步：完成
    //标记RPC准备工作完成:在开始会出现SetRPCWarmupFinished()函数，该函数在/server.h中声明，在/server.cpp中实现。
    SetRPCWarmupFinished();
    //显示加载完成:uiInterface.InitMessage(_("Done loading")这行代码功能就是在界面显示"Done loading"(加载完成)，写入日志文件中。
    uiInterface.InitMessage(_("Done loading"));
    //重新接受钱包交易:postInitProcess()函数在wallet.h定义
#ifdef ENABLE_WALLET
    StartWallets(scheduler);
#endif
    //第十二步总结:该部分是整个初始化的最后步骤，标志着初始化的完成。主要包含RPC开始工作、显示加载完成和重新接收钱包的交易工作。
    //至此初始化最重要的函数AppInitMain()就全部完成了。
    return true;
}
