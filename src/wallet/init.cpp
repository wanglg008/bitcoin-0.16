// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/init.h>

#include <net.h>
#include <util.h>
#include <utilmoneystr.h>
#include <validation.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

std::string GetWalletHelpString(bool showDebug)
{
    std::string strUsage = HelpMessageGroup(_("Wallet options:"));
    strUsage += HelpMessageOpt("-addresstype", strprintf("What type of addresses to use (\"legacy\", \"p2sh-segwit\", or \"bech32\", default: \"%s\")", FormatOutputType(OUTPUT_TYPE_DEFAULT)));
    strUsage += HelpMessageOpt("-changetype", "What type of change to use (\"legacy\", \"p2sh-segwit\", or \"bech32\"). Default is same as -addresstype, except when -addresstype=p2sh-segwit a native segwit output is used when sending to a native segwit address)");
    strUsage += HelpMessageOpt("-disablewallet", _("Do not load the wallet and disable wallet RPC calls"));
    strUsage += HelpMessageOpt("-keypool=<n>", strprintf(_("Set key pool size to <n> (default: %u)"), DEFAULT_KEYPOOL_SIZE));
    strUsage += HelpMessageOpt("-fallbackfee=<amt>", strprintf(_("A fee rate (in %s/kB) that will be used when fee estimation has insufficient data (default: %s)"),
                                                               CURRENCY_UNIT, FormatMoney(DEFAULT_FALLBACK_FEE)));
    strUsage += HelpMessageOpt("-discardfee=<amt>", strprintf(_("The fee rate (in %s/kB) that indicates your tolerance for discarding change by adding it to the fee (default: %s). "
                                                                "Note: An output is discarded if it is dust at this rate, but we will always discard up to the dust relay fee and a discard fee above that is limited by the fee estimate for the longest target"),
                                                              CURRENCY_UNIT, FormatMoney(DEFAULT_DISCARD_FEE)));
    strUsage += HelpMessageOpt("-mintxfee=<amt>", strprintf(_("Fees (in %s/kB) smaller than this are considered zero fee for transaction creation (default: %s)"),
                                                            CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MINFEE)));
    strUsage += HelpMessageOpt("-paytxfee=<amt>", strprintf(_("Fee (in %s/kB) to add to transactions you send (default: %s)"),
                                                            CURRENCY_UNIT, FormatMoney(payTxFee.GetFeePerK())));
    strUsage += HelpMessageOpt("-rescan", _("Rescan the block chain for missing wallet transactions on startup"));
    strUsage += HelpMessageOpt("-salvagewallet", _("Attempt to recover private keys from a corrupt wallet on startup"));
    strUsage += HelpMessageOpt("-spendzeroconfchange", strprintf(_("Spend unconfirmed change when sending transactions (default: %u)"), DEFAULT_SPEND_ZEROCONF_CHANGE));
    strUsage += HelpMessageOpt("-txconfirmtarget=<n>", strprintf(_("If paytxfee is not set, include enough fee so transactions begin confirmation on average within n blocks (default: %u)"), DEFAULT_TX_CONFIRM_TARGET));
    strUsage += HelpMessageOpt("-walletrbf", strprintf(_("Send transactions with full-RBF opt-in enabled (RPC only, default: %u)"), DEFAULT_WALLET_RBF));
    strUsage += HelpMessageOpt("-upgradewallet", _("Upgrade wallet to latest format on startup"));
    strUsage += HelpMessageOpt("-wallet=<file>", _("Specify wallet file (within data directory)") + " " + strprintf(_("(default: %s)"), DEFAULT_WALLET_DAT));
    strUsage += HelpMessageOpt("-walletbroadcast", _("Make the wallet broadcast transactions") + " " + strprintf(_("(default: %u)"), DEFAULT_WALLETBROADCAST));
    strUsage += HelpMessageOpt("-walletdir=<dir>", _("Specify directory to hold wallets (default: <datadir>/wallets if it exists, otherwise <datadir>)"));
    strUsage += HelpMessageOpt("-walletnotify=<cmd>", _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)"));
    strUsage += HelpMessageOpt("-zapwallettxes=<mode>", _("Delete all wallet transactions and only recover those parts of the blockchain through -rescan on startup") +
                               " " + _("(1 = keep tx meta data e.g. account owner and payment request information, 2 = drop tx meta data)"));

    if (showDebug)
    {
        strUsage += HelpMessageGroup(_("Wallet debugging/testing options:"));

        strUsage += HelpMessageOpt("-dblogsize=<n>", strprintf("Flush wallet database activity from memory to disk log every <n> megabytes (default: %u)", DEFAULT_WALLET_DBLOGSIZE));
        strUsage += HelpMessageOpt("-flushwallet", strprintf("Run a thread to flush wallet periodically (default: %u)", DEFAULT_FLUSHWALLET));
        strUsage += HelpMessageOpt("-privdb", strprintf("Sets the DB_PRIVATE flag in the wallet db environment (default: %u)", DEFAULT_WALLET_PRIVDB));
        strUsage += HelpMessageOpt("-walletrejectlongchains", strprintf(_("Wallet will not create transactions that violate mempool chain limits (default: %u)"), DEFAULT_WALLET_REJECT_LONG_CHAINS));
    }

    return strUsage;
}

bool WalletParameterInteraction()
{
    //1）-disablewallet：禁用钱包功能（默认为false，即打开钱包功能）。在运行时设置了-disablewallet参数，我们的钱包功能将被关闭，
    //将不会加载钱包，同时禁用钱包的RPC调用，程序也将返回，并停止运行。
    if (gArgs.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET)) {
        for (const std::string& wallet : gArgs.GetArgs("-wallet")) {
            LogPrintf("%s: parameter interaction: -disablewallet -> ignoring -wallet=%s\n", __func__, wallet);
        }

        return true;
    }

    gArgs.SoftSetArg("-wallet", DEFAULT_WALLET_DAT);
    const bool is_multiwallet = gArgs.GetArgs("-wallet").size() > 1;

    //2）-blocksonly：只以区块模式运行（比特币客户端以调试状态启动时才会使用。就是节点不接收临时的交易，只接受已确认的区块）。
    //默认为false，即默认不会只以区块模式运行，因为如果在区块模式下运行，全网的交易将不会被打包，钱包的交易广播功能将失效。
    if (gArgs.GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY) && gArgs.SoftSetBoolArg("-walletbroadcast", false)) {
        LogPrintf("%s: parameter interaction: -blocksonly=1 -> setting -walletbroadcast=0\n", __func__);
    }

    //3）-salvagewallet：该参数的功能为试图在比特币客户端启动时从损坏的钱包中恢复私钥。该参数只有用-rescan参数启动客户端的情况下才能生效。
    if (gArgs.GetBoolArg("-salvagewallet", false)) {
        if (is_multiwallet) {
            return InitError(strprintf("%s is only allowed with a single wallet file", "-salvagewallet"));
        }
        // Rewrite just private keys: rescan to find transactions
        if (gArgs.SoftSetBoolArg("-rescan", true)) {
            LogPrintf("%s: parameter interaction: -salvagewallet=1 -> setting -rescan=1\n", __func__);
        }
    }

    //4）-zapwallettxes：参数用于删除钱包的所有交易记录，且只有用-rescan参数启动客户端才能重新取回交易记录，且只有用
    //-rescan参数启动客户端才能重新取回交易记录。
    int zapwallettxes = gArgs.GetArg("-zapwallettxes", 0);
    // -zapwallettxes implies dropping the mempool on startup
    if (zapwallettxes != 0 && gArgs.SoftSetBoolArg("-persistmempool", false)) {
        LogPrintf("%s: parameter interaction: -zapwallettxes=%s -> setting -persistmempool=0\n", __func__, zapwallettxes);
    }

    // -zapwallettxes implies a rescan
    if (zapwallettxes != 0) {
        if (is_multiwallet) {
            return InitError(strprintf("%s is only allowed with a single wallet file", "-zapwallettxes"));
        }
        if (gArgs.SoftSetBoolArg("-rescan", true)) {
            LogPrintf("%s: parameter interaction: -zapwallettxes=%s -> setting -rescan=1\n", __func__, zapwallettxes);
        }
    }

    if (is_multiwallet) {
        if (gArgs.GetBoolArg("-upgradewallet", false)) {
            return InitError(strprintf("%s is only allowed with a single wallet file", "-upgradewallet"));
        }
    }

    //5）-sysperms：这个前面已经提到过了，在这里是该参数不能和钱包功能开启状态同时出现，会冲突，导致程序退出。
    if (gArgs.GetBoolArg("-sysperms", false))
        return InitError("-sysperms is not allowed in combination with enabled wallet functionality");
    //6）-prune与-rescan：使用-rescan参数启动时，是不能用-prune参数的，否则二者将会冲突，程序自动退出。
    if (gArgs.GetArg("-prune", 0) && gArgs.GetBoolArg("-rescan", false))
        return InitError(_("Rescans are not possible in pruned mode. You will need to use -reindex which will download the whole blockchain again."));

    //7）-minRelayTxFee：（参考前面的（20））此处用法是：防止用户设置的最低手续费高于比特币程序中设置的最高手续费（0.01个比特币），
    //导致手续费过高，影响比特币网络的正常运转。
    if (::minRelayTxFee.GetFeePerK() > HIGH_TX_FEE_PER_KB)
        InitWarning(AmountHighWarn("-minrelaytxfee") + " " +
                    _("The wallet will avoid paying less than the minimum relay fee."));

    //8）-mintxfee：最低手续费不应高于最高手续费，否则程序将给出警告提示。
    if (gArgs.IsArgSet("-mintxfee"))
    {
        CAmount n = 0;
        if (!ParseMoney(gArgs.GetArg("-mintxfee", ""), n) || 0 == n)
            return InitError(AmountErrMsg("mintxfee", gArgs.GetArg("-mintxfee", "")));
        if (n > HIGH_TX_FEE_PER_KB)
            InitWarning(AmountHighWarn("-mintxfee") + " " +
                        _("This is the minimum transaction fee you pay on every transaction."));
        CWallet::minTxFee = CFeeRate(n);
    }
    //9）-fallbackfee：当交易池中没有足够数据支撑手续费的估算时，就使用-fallbackFee作为较低最低收取费。
    if (gArgs.IsArgSet("-fallbackfee"))
    {
        CAmount nFeePerK = 0;
        if (!ParseMoney(gArgs.GetArg("-fallbackfee", ""), nFeePerK))
            return InitError(strprintf(_("Invalid amount for -fallbackfee=<amount>: '%s'"), gArgs.GetArg("-fallbackfee", "")));
        //10）-paytxfee与-maxtxfee：分别是支付交易手续费与最高交易手续费。此处判断，若低于支付交易手续费则程序退出；
        //若高于最高交易手续费，则警告超出了最高手续费。
        if (nFeePerK > HIGH_TX_FEE_PER_KB)
            InitWarning(AmountHighWarn("-fallbackfee") + " " +
                        _("This is the transaction fee you may pay when fee estimates are not available."));
        CWallet::fallbackFee = CFeeRate(nFeePerK);
    }
    if (gArgs.IsArgSet("-discardfee"))
    {
        CAmount nFeePerK = 0;
        if (!ParseMoney(gArgs.GetArg("-discardfee", ""), nFeePerK))
            return InitError(strprintf(_("Invalid amount for -discardfee=<amount>: '%s'"), gArgs.GetArg("-discardfee", "")));
        if (nFeePerK > HIGH_TX_FEE_PER_KB)
            InitWarning(AmountHighWarn("-discardfee") + " " +
                        _("This is the transaction fee you may discard if change is smaller than dust at this level"));
        CWallet::m_discard_rate = CFeeRate(nFeePerK);
    }
    if (gArgs.IsArgSet("-paytxfee"))
    {
        CAmount nFeePerK = 0;
        if (!ParseMoney(gArgs.GetArg("-paytxfee", ""), nFeePerK))
            return InitError(AmountErrMsg("paytxfee", gArgs.GetArg("-paytxfee", "")));
        if (nFeePerK > HIGH_TX_FEE_PER_KB)
            InitWarning(AmountHighWarn("-paytxfee") + " " +
                        _("This is the transaction fee you will pay if you send a transaction."));

        payTxFee = CFeeRate(nFeePerK, 1000);
        if (payTxFee < ::minRelayTxFee)
        {
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s' (must be at least %s)"),
                                       gArgs.GetArg("-paytxfee", ""), ::minRelayTxFee.ToString()));
        }
    }
    if (gArgs.IsArgSet("-maxtxfee"))
    {
        CAmount nMaxFee = 0;
        if (!ParseMoney(gArgs.GetArg("-maxtxfee", ""), nMaxFee))
            return InitError(AmountErrMsg("maxtxfee", gArgs.GetArg("-maxtxfee", "")));
        if (nMaxFee > HIGH_MAX_TX_FEE)
            InitWarning(_("-maxtxfee is set very high! Fees this large could be paid on a single transaction."));
        maxTxFee = nMaxFee;
        if (CFeeRate(maxTxFee, 1000) < ::minRelayTxFee)
        {
            return InitError(strprintf(_("Invalid amount for -maxtxfee=<amount>: '%s' (must be at least the minrelay fee of %s to prevent stuck transactions)"),
                                       gArgs.GetArg("-maxtxfee", ""), ::minRelayTxFee.ToString()));
        }
    }
    //11）-txconfirmtarget：比特币的每一笔交易都需要经过n（默认为6）次区块确认才能算真正的交易成功了，且不能回退。
    nTxConfirmTarget = gArgs.GetArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);
    //12）-spendzeroconfchange：表示比特币客户端是否可以花费0确认的费用（默认true）。
    bSpendZeroConfChange = gArgs.GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);
    //13）-walletrbf：它可以为钱包产生的所有新交易添加交易费，具体是指BIP125可选费用替代法（RBF）。这一功能可为先前未确认的
    //交易添加手续费，以加大交易被确认的机会。默认是关闭的，如果想开启用在客户端用bitcoind -walletrbf命令。
    fWalletRbf = gArgs.GetBoolArg("-walletrbf", DEFAULT_WALLET_RBF);

    g_address_type = ParseOutputType(gArgs.GetArg("-addresstype", ""));
    if (g_address_type == OUTPUT_TYPE_NONE) {
        return InitError(strprintf("Unknown address type '%s'", gArgs.GetArg("-addresstype", "")));
    }

    // If changetype is set in config file or parameter, check that it's valid.
    // Default to OUTPUT_TYPE_NONE if not set.
    g_change_type = ParseOutputType(gArgs.GetArg("-changetype", ""), OUTPUT_TYPE_NONE);
    if (g_change_type == OUTPUT_TYPE_NONE && !gArgs.GetArg("-changetype", "").empty()) {
        return InitError(strprintf("Unknown change type '%s'", gArgs.GetArg("-changetype", "")));
    }

    return true;
}

void RegisterWalletRPC(CRPCTable &t)
{
    if (gArgs.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET)) {
        return;
    }

    RegisterWalletRPCCommands(t);
}

bool VerifyWallets()
{
    //首先判断命令行中是否含有-disablewallet命令，如果含有这个命令则表示禁用了钱包功能，那么就没有接下来检查完整性的必要了，
    //就直接返回true，结束该函数。
    if (gArgs.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET)) {
        return true;
    }

    if (gArgs.IsArgSet("-walletdir")) {
        fs::path wallet_dir = gArgs.GetArg("-walletdir", "");
        if (!fs::exists(wallet_dir)) {
            return InitError(strprintf(_("Specified -walletdir \"%s\" does not exist"), wallet_dir.string()));
        } else if (!fs::is_directory(wallet_dir)) {
            return InitError(strprintf(_("Specified -walletdir \"%s\" is not a directory"), wallet_dir.string()));
        } else if (!wallet_dir.is_absolute()) {
            return InitError(strprintf(_("Specified -walletdir \"%s\" is a relative path"), wallet_dir.string()));
        }
    }
    
    LogPrintf("Using wallet directory %s\n", GetWalletDir().string());

    uiInterface.InitMessage(_("Verifying wallet(s)..."));

    // Keep track of each wallet absolute path to detect duplicates.        跟踪每个钱包绝对路径以检测重复项。
    std::set<fs::path> wallet_paths;
    //接下来对于命令行中传入的每一个钱包路径，首先检查文件的路径、是否包含非法字符、是否是regular file或者链接、是否有相同的文件等。
    for (const std::string& walletFile : gArgs.GetArgs("-wallet")) {
        if (boost::filesystem::path(walletFile).filename() != walletFile) {
            return InitError(strprintf(_("Error loading wallet %s. -wallet parameter must only specify a filename (not a path)."), walletFile));
        }

        if (SanitizeString(walletFile, SAFE_CHARS_FILENAME) != walletFile) {
            return InitError(strprintf(_("Error loading wallet %s. Invalid characters in -wallet filename."), walletFile));
        }

        fs::path wallet_path = fs::absolute(walletFile, GetWalletDir());

        if (fs::exists(wallet_path) && (!fs::is_regular_file(wallet_path) || fs::is_symlink(wallet_path))) {
            return InitError(strprintf(_("Error loading wallet %s. -wallet filename must be a regular file."), walletFile));
        }

        if (!wallet_paths.insert(wallet_path).second) {
            return InitError(strprintf(_("Error loading wallet %s. Duplicate -wallet filename specified."), walletFile));
        }
        //然后用CWalletDB::VerifyEnvironment()函数验证钱包的环境。该函数传入钱包文件名和钱包的绝对路径，首先检查钱包文件名是否是不
        //包含路径的纯文件名，接下来调用一个CDBEnv类型变量bitdb中的open函数（open函数首先检查数据库文件是否存在，不存在就立即创建；
        //然后设置日志文件，并且通过DbEnv类型变量指针dbenv设置了一系列数据库运行的相关参数）。open函数执行成功的话，就直接返回true；
        //否则就进入if语句，之后首先将原来的钱包数据库文件进行备份，然后再次尝试调用open函数，创建数据库文件。
        std::string strError;
        if (!CWalletDB::VerifyEnvironment(walletFile, GetWalletDir().string(), strError)) {
            return InitError(strError);
        }

        //然后会有一个判断是否含有-salvagewallet命令的判断语句，其中-salvagewallet命令通过参照帮助文件可以知道它的作用是：尝试在启动
        //时从损坏的钱包中恢复私钥。所以后面的代码都是执行在钱包中恢复私钥的作用的，这个工作是由CWalletDB::Recover()函数完成的。这个函
        //数中有4个重要的参数：filename：待恢复的钱包文件名；callbackDataIn：恢复数据写入对象；recoverKVcallback：回调函数，用来将
        //恢复数据写入callbackDataIn；newFilename：备份文件名。
        //私钥恢复的步骤是首先备份原来的钱包文件，然后调用CDBEnv类中的Salvage函数，这个函数实现的功能是从文件中将公私钥读取出来并保存
        //在到salvagedData中。恢复完之后就将恢复的数据写入到本地数据库中，这个写入的过程都是通过pdbCopy对象来进行的，同时如果定义
        //了recoverKVcallback函数，那么还同时写入到callbackDataIn对象中，用于传给上层调用函数。
        if (gArgs.GetBoolArg("-salvagewallet", false)) {
            // Recover readable keypairs:                   恢复可读密钥对：
            CWallet dummyWallet;
            std::string backup_filename;
            if (!CWalletDB::Recover(walletFile, (void *)&dummyWallet, CWalletDB::RecoverKeysOnlyFilter, backup_filename)) {
                return false;
            }
        }
        //最后会出现一个CWalletDB::VerifyDatabaseFile()函数，这个函数主要是用来验证数据库文件的。这个函数的最终实现是：如果验证通过
        //的话那么就直接返回VERIFY_OK；否则就先看是否设置了恢复函数，如果没有就返回RECOVER_FAIL；如果设置了恢复函数，那么就调用恢复
        //函数，并返回恢复函数执行的结果。由前面可以发现恢复函数被设置成了CWalletDB::Recover函数，所以这里都会调用这个函数。
        std::string strWarning;
        bool dbV = CWalletDB::VerifyDatabaseFile(walletFile, GetWalletDir().string(), strWarning, strError);
        if (!strWarning.empty()) {
            InitWarning(strWarning);
        }
        if (!dbV) {
            InitError(strError);
            return false;
        }
    }

    return true;
}
//该函数首先判断是否在启动程序时添加了-disablewallet参数命令，如果有该命令，就不用加载钱包了。然后如果没有该命令，就使用
//一个for循环语句加载钱包：for循环开始是遍历-wallet参数数组后面的元素，一次赋值给walletFile变量；然后用该变量当作输入调
//用CreateWalletFromFile()函数来加载钱包；
bool OpenWallets()
{
    if (gArgs.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET)) {
        LogPrintf("Wallet disabled!\n");
        return true;
    }

    for (const std::string& walletFile : gArgs.GetArgs("-wallet")) {
        CWallet * const pwallet = CWallet::CreateWalletFromFile(walletFile);
        if (!pwallet) {
            return false;
        }
        vpwallets.push_back(pwallet);//并把加载的钱包拷贝添加到vpwallets（是一个vector类变量）容器的后面。
    }

    return true;
}

void StartWallets(CScheduler& scheduler) {
    for (CWalletRef pwallet : vpwallets) {
        pwallet->postInitProcess(scheduler);
    }
}

void FlushWallets() {
    for (CWalletRef pwallet : vpwallets) {
        pwallet->Flush(false);
    }
}

void StopWallets() {
    for (CWalletRef pwallet : vpwallets) {
        pwallet->Flush(true);
    }
}

void CloseWallets() {
    for (CWalletRef pwallet : vpwallets) {
        delete pwallet;
    }
    vpwallets.clear();
}
