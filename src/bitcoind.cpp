// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <chainparams.h>
#include <clientversion.h>
#include <compat.h>
#include <fs.h>
#include <rpc/server.h>
#include <init.h>
#include <noui.h>
#include <util.h>
#include <httpserver.h>
#include <httprpc.h>
#include <utilstrencodings.h>

#include <boost/thread.hpp>//boost::thread_group是一个管理一组线程的类，它由boost库提供，可以实现对多个线程统一管理。

#include <stdio.h>

/* Introduction text for doxygen: */

/*! \mainpage Developer documentation
 *
 * \section intro_sec Introduction
 *
 * This is the developer documentation of the reference client for an experimental new digital currency called Bitcoin (https://www.bitcoin.org/),
 * which enables instant payments to anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
 * with no central authority: managing transactions and issuing money are carried out collectively by the network.
 *
 * The software is a community-driven open source project, released under the MIT license.
 *
 * \section Navigation
 * Use the buttons <code>Namespaces</code>, <code>Classes</code> or <code>Files</code> at the top of the page to start navigating the code.
 */
//主要是循环检测关闭命令
void WaitForShutdown()
{
    bool fShutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (!fShutdown)
    {
        MilliSleep(200);
        fShutdown = ShutdownRequested();
    }
    Interrupt();
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//该函数标志着比特币程序真正的开始。函数的返回值类型为bool类型，输入的参数为一个整数型参数和一个元素是字符指针的数组类型参数。
bool AppInit(int argc, char* argv[])
{
    bool fRet = false;

    //
    // Parameters
    //
    // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main()
    gArgs.ParseParameters(argc, argv);  //解析命令行参数

    // Process help and version before taking care about datadir
    // 处理数据目录操作前，先完成版本与帮助命令的处理。通过这段代码，比特币后台进程可以根据用户输入的相应参数来输出对应的版本与帮助信息。
    if (gArgs.IsArgSet("-?") || gArgs.IsArgSet("-h") ||  gArgs.IsArgSet("-help") || gArgs.IsArgSet("-version"))
    {
        //通过strUsage字符串变量存储包含比特币后台进程名称与版本信息内容。
        std::string strUsage = strprintf(_("%s Daemon"), _(PACKAGE_NAME)) + " " + _("version") + " " + FormatFullVersion() + "\n";

        if (gArgs.IsArgSet("-version"))
        {
            strUsage += FormatParagraph(LicenseInfo());
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  bitcoind [options]                     " + strprintf(_("Start %s Daemon"), _(PACKAGE_NAME)) + "\n";
            //参数HMM_BITCOIND为比特币的后台进程帮助信息,它的定义在init.h中
            strUsage += "\n" + HelpMessage(HMM_BITCOIND);   
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return true;
    }

    //逻辑如下所示:(1)判断函数GetDataDir()得到的数据路径是否为规范的目录名称。如果不是，打印指定目录不存在的错误信息，并返回false值，程序退出；如果是，则继续下面的程序。
    //(2)使用ReadConfigFile()函数读取配置文件中的参数与参数值，并把得到的参数信息存入mapArgs和_mapMultiArgs中。
    try
    {   //判断数据目录是否存在并读取配置文件参数指定的配置文件
        if (!fs::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", gArgs.GetArg("-datadir", "").c_str());
            return false;
        }
        try
        {
            //BITCOIN_CONF_FILENAME在util.cpp中定义。判断是否有参数"-conf"，如果有则使用前面ParseParmeters()函数使用后保存的参数值作为配置文件；如果没有，则使用默认的“bitcoin.conf”。
            gArgs.ReadConfigFile(gArgs.GetArg("-conf", BITCOIN_CONF_FILENAME)); 
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }

        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause) 
        // 检查- testnet或- regtest参数 (Params()调用仅在此子句之后有效)。其中-testnet指代比特币的测试网络Testnet，而-regtest指代比特币的私有网络Regression test。
        // 那么可以知道该部分是选择比特币网络。
        try {
            //想要创建自己需要的数字货币，只需要单独修改这里面的参数就行，比如修改难度，奖励金额等。这个部分是开发时经常要修改的地方。
            SelectParams(ChainNameFromCommandLine());   //检查-testnet or -regtest参数
        } catch (const std::exception& e) {
            fprintf(stderr, "Error: %s\n", e.what());
            return false;
        }

        // Error out when loose non-argument tokens are encountered on command line 当命令行中有不准确的无参数符号时出现错误提示。
        for (int i = 1; i < argc; i++) {     //如果符号不正确，则在终端输出错误，而且程序会因为异常而退出。
            if (!IsSwitchChar(argv[i][0])) {
                fprintf(stderr, "Error: Command line contains unexpected token '%s', see bitcoind -h for a list of options.\n", argv[i]);
                return false;
            }
        }

        // -server defaults to true for bitcoind but not for the GUI so do this here
        // 对于bitcoind来说-server默认是开启的，但对于GUI（图形界面）-server默认则是关闭的，所以在此添加代码。
        gArgs.SoftSetBoolArg("-server", true); //解析mapArgs参数，判断其中是否有-server这个参数，如果存在就无需设置；如果没有这个参数，就根据SoftSetBoolArg()传入的fValue值进行设置。
        // Set this early so that parameter interactions go to console  //提前设置这部分，使参数交互内容进入控制台中。
        InitLogging();              //初始化日志基础设施
        InitParameterInteraction(); //参数交互:根据不同的规则改变当前参数。

        //AppInitBasicSetup()函数总结：当用微软的VS编译时对它的警告消息进行处理，并把异常正常抛给异常捕获函数；在Windows系统中开启
        //DEP功能保护数据安全；初始化网络的连接，启动Winsock服务，使之后的Sockets连接涉及的API能被正常调用；在非Windows系统下判断并
        //设置文件与文件夹使用权限，关闭SIGTERM信号，挂起SIGHUP信号并重新打开调试日志打印我文件，忽略SIGPIPE信号防止引起错误；当内存
        //失败时直接终止程序防止区块链被破坏，并进行日志打印；最终函数返回true；结束。
        if (!AppInitBasicSetup())
        {
            // InitError will have been called with detailed error, which ends up on console
            // InitError将被调用，并有详细的错误，最终将在控制台结束
            return false;
        }

        if (!AppInitParameterInteraction())
        {
            // InitError will have been called with detailed error, which ends up on console
            return false;
        }

        //总结：主要分为三个部分：首先是初始化椭圆曲线密码（ECC），为一系列的准备工作——选择SHA256准备、随机数生成器准备、椭圆曲线功能
        //开启、验证椭圆曲线开启和重置内存，都是为了下一步做准备工作；然后是InitSanityCheck()函数进行的健全性检查——包括椭圆曲线加密
        //结果的完整性验证、验证当前运行环境是否支持C/C++运行环境和验证系统的随机数生成器是否可用，是此步骤的核心；
        //最后是AppInitSanityChecks()函数控制的目录锁检查——确保只有一个比特币进程正在使用数据目录，也是确保只有一个bitcoind运行。
        if (!AppInitSanityChecks())
        {
            // InitError will have been called with detailed error, which ends up on console //InitError将被调用，并有详细的错误，最终将在控制台结束
            return false;
        }
        
        //首先if条件语句判断是否在启动时设置了守护进程-daemon参数，如果设置了则该参数使用设置的代码，并且继续下面的代码；否则返回false。
        if (gArgs.GetBoolArg("-daemon", false))
        {
            //HAVE_DECL_DAEMON宏定义在未经编译的源码中是不包含的，需经过./configure配置后才会出现，该定义
            //位于config/bitcoin-config.h的106行，默认为1，表示定义了daemon；如果为0则为不定义daemon。
            //用条件编译判断是否包含HAVE_DECL_DAEMON宏，包含则继续下面的代码；不包含则将在控制台中输出当前系统不支持守护进程的错误提示。
#if HAVE_DECL_DAEMON
            //如果包含HAVE_DECL_DAEMON宏定义，且该值为1，则在控制台中输出"Bitcoin server starting"信息，表明比特币后台守护进程在运行。
            fprintf(stdout, "Bitcoin server starting\n");

            // Daemonize  后台运行
            //然后再判断daemon(1, 0)函数的返回值，如果返回值为非零，则输出errorno对应的错误提示，并返回false，程序退出；如果daemon()函数返回为0时则正常运行。
            if (daemon(1, 0)) { // don't chdir (1), do close FDs (0) 
                fprintf(stderr, "Error: daemon() failed: %s\n", strerror(errno));
                return false;
            }
#else
            fprintf(stderr, "Error: -daemon is not supported on this operating system\n");
            return false;
#endif // HAVE_DECL_DAEMON
        }

        // Lock data directory after daemonization                      在守护进程后锁定数据目录。
        if (!AppInitLockDataDirectory())
        {
            // If locking the data directory failed, exit immediately   如果锁定数据目录失败，立即退出
            return false;
        }
        fRet = AppInitMain();
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInit()");
    }

    if (!fRet)
    {
        Interrupt();
    } else {
        WaitForShutdown();
    }
    Shutdown();

    return fRet;
}

int main(int argc, char* argv[])
{
    SetupEnvironment();     //设置本地的运行环境

    // Connect bitcoind signal handlers
    noui_connect();         //连接客户端的信号处理程序

    return (AppInit(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE); //主初始化程序
}
