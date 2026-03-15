#pragma once

#include <string>
#include <vector>
#include <sqlite3.h>
#include <unordered_map>
#include "CryptoModule.h"
#include "ProtocolMessages.h"
#include "SecureRecordLayer.h"

// 模拟服务器数据库中存储的用户记录表 (avk)
struct UserRecord {
    CryptoModule::Bytes pkSig; // 用户的签名公钥 (用于验证用户身份)
    CryptoModule::Bytes skEnc; // 用户的解密私钥 (服务器托管，用于解密 tau)
};

// 维护认证过程中的临时会话上下文 (保证前向安全性)
struct AuthSession {
    CryptoModule::KeyPair tempDH;     // 服务器的临时 DH 密钥对 (dhprivS, dhpubS)
    CryptoModule::Bytes serversigm;   // 服务器对 DH 公钥的签名
    CryptoModule::Bytes sharedSecret; // 协商出的共享秘密
    CryptoModule::Bytes sessionKey;   // 最终派生的会话密钥
    SecureRecordLayer secureLayer;
};

class Server {
public:
    // 初始化服务器，生成长期签名密钥对 [cite: 144-146]
    Server();
    ~Server();
    // ==========================================
    // 注册阶段
    // ==========================================
    
    // 处理用户注册请求，将 avk 存入数据库，并返回服务器长期公钥 [cite: 163-166]
    ProtocolMessages::RegistrationResponse ProcessRegistration(
        const ProtocolMessages::RegistrationRequest& req
    );

    // ==========================================
    // 认证与密钥协商阶段
    // ==========================================
    
    // 步骤 2: 响应用户的登录请求，生成并下发挑战 (包含临时 DH 公钥和签名) [cite: 175-178]
    ProtocolMessages::AuthChallenge GenerateAuthChallenge(const std::string& uid);

    // 步骤 4: 接收用户的响应，执行解密、验签、共享秘密计算与标签确认 [cite: 192-201]
    ProtocolMessages::AuthConfirmation ProcessAuthResponse(
        const ProtocolMessages::AuthResponse& resp
    );

    // 获取特定用户的会话密钥 (用于测试验证)
    CryptoModule::Bytes GetSessionKey(const std::string& uid) const;
// 模拟内存缓存：uid -> AuthSession (当前正在进行的认证会话)
    std::unordered_map<std::string, AuthSession> m_activeSessions;
    // 专为测试流程设计的：清空数据库
    void ClearDatabase();

private:
    // 服务器的长期身份密钥
    CryptoModule::KeyPair m_longTermKeys;

    // 模拟数据库：uid -> UserRecord (avk)
    //std::unordered_map<std::string, UserRecord> m_database;

    

    //数据库连接句柄
    sqlite3* m_db = nullptr;

    //内部辅助函数：初始化数据库建表
    void InitDatabase();
};