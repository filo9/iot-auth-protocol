#include "Server.h"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>

// ==========================================
// 【新增】：引入 main_server.cpp 中的广播功能与 Hex 转换工具
// ==========================================
extern void BroadcastToMonitor(const std::string& event, const std::string& title, const std::string& details);

static std::string ToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (unsigned char b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

// ==========================================
// 构造、析构与数据库初始化
// ==========================================
Server::Server() {
    m_longTermKeys = CryptoModule::GenerateSignatureKeyPair({});
    InitDatabase();
}

Server::~Server() {
    if (m_db) sqlite3_close(m_db);
}

void Server::InitDatabase() {
    if (sqlite3_open("server_data.db", &m_db) != SQLITE_OK) {
        throw std::runtime_error("Can't open database: " + std::string(sqlite3_errmsg(m_db)));
    }
    const char* sql_create_table = 
        "CREATE TABLE IF NOT EXISTS users ("
        "uid TEXT PRIMARY KEY NOT NULL, "
        "pkSig BLOB NOT NULL, "
        "skEnc BLOB NOT NULL);";
    char* errMsg = nullptr;
    if (sqlite3_exec(m_db, sql_create_table, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::string errStr(errMsg);
        sqlite3_free(errMsg);
        throw std::runtime_error("SQL error on creating table: " + errStr);
    }
}

void Server::ClearDatabase() {
    const char* sql_clear = "DELETE FROM users;";
    char* errMsg = nullptr;
    if (sqlite3_exec(m_db, sql_clear, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        sqlite3_free(errMsg);
        throw std::runtime_error("Failed to clear database.");
    }
    m_activeSessions.clear(); 
    std::cout << "[Server] Database and active sessions cleared successfully.\n";
}

// ==========================================
// 注册阶段
// ==========================================
ProtocolMessages::RegistrationResponse Server::ProcessRegistration(
    const ProtocolMessages::RegistrationRequest& req) 
{
    const char* sql_check = "SELECT uid FROM users WHERE uid = ?;";
    sqlite3_stmt* stmt_check;
    if (sqlite3_prepare_v2(m_db, sql_check, -1, &stmt_check, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt_check, 1, req.uid.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt_check) == SQLITE_ROW) {
            sqlite3_finalize(stmt_check);
            throw std::runtime_error("UID [" + req.uid + "] 已被注册！每个设备只能注册一次。");
        }
        sqlite3_finalize(stmt_check);
    }

    const char* sql_insert = "INSERT INTO users (uid, pkSig, skEnc) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql_insert, -1, &stmt, nullptr) != SQLITE_OK) throw std::runtime_error("Failed to prepare insert statement");
    
    sqlite3_bind_text(stmt, 1, req.uid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, req.avk_pkSig.data(), req.avk_pkSig.size(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, req.avk_skEnc.data(), req.avk_skEnc.size(), SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to insert user into database");
    }
    sqlite3_finalize(stmt);

    ProtocolMessages::RegistrationResponse resp;
    resp.success = true;
    resp.serversigpk = m_longTermKeys.publicKey;
    return resp;
}

// ==========================================
// 认证与密钥协商阶段
// ==========================================
ProtocolMessages::AuthChallenge Server::GenerateAuthChallenge(const std::string& uid) {
    const char* sql_select = "SELECT uid FROM users WHERE uid = ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(m_db, sql_select, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, uid.c_str(), -1, SQLITE_TRANSIENT);

    bool userExists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    if (!userExists) throw std::runtime_error("User not found in real database.");

    AuthSession session;
    session.tempDH = CryptoModule::GenerateDHKeyPair();
    session.serversigm = CryptoModule::Sign(m_longTermKeys.privateKey, session.tempDH.publicKey);
    m_activeSessions[uid] = session;

    ProtocolMessages::AuthChallenge challenge;
    challenge.dhpubS = session.tempDH.publicKey;
    challenge.serversigm = session.serversigm;
    return challenge;
}

ProtocolMessages::AuthConfirmation Server::ProcessAuthResponse(const ProtocolMessages::AuthResponse& resp) {
    ProtocolMessages::AuthConfirmation confirmation;
    confirmation.success = false;

    const char* sql_select = "SELECT pkSig, skEnc FROM users WHERE uid = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql_select, -1, &stmt, nullptr) != SQLITE_OK) throw std::runtime_error("Database read error");
    sqlite3_bind_text(stmt, 1, resp.uid.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return confirmation; 
    }

    const uint8_t* pkSigBlob = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
    CryptoModule::Bytes db_pkSig(pkSigBlob, pkSigBlob + sqlite3_column_bytes(stmt, 0));
    const uint8_t* skEncBlob = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 1));
    CryptoModule::Bytes db_skEnc(skEncBlob, skEncBlob + sqlite3_column_bytes(stmt, 1));
    sqlite3_finalize(stmt);

    auto sessionIt = m_activeSessions.find(resp.uid);
    if (sessionIt == m_activeSessions.end()) return confirmation;
    AuthSession& session = sessionIt->second;

    // ==========================================
    // 追踪 1：收到密文包裹
    // ==========================================
    std::string auditMsg1 = "【密文包裹 tau】:\n" + ToHex(resp.tau) + "\n\n";
    auditMsg1 += "【确认标签 tagU】:\n" + ToHex(resp.tagU) + "\n\n";
    auditMsg1 += "⚠️ 准备使用数据库存储的 sk_Enc 解密 tau。若终端指纹/口令错误引发了变异密钥，此步骤将立即崩溃拦截！";
    BroadcastToMonitor("warning", "📥 1. 收到终端认证挑战响应", auditMsg1);

    // ==========================================
    // 解密 tau 提取 sigma 和 dhpubU
    // ==========================================
    CryptoModule::Bytes decryptedPlaintext = CryptoModule::Decrypt(db_skEnc, resp.tau);
    
    if (decryptedPlaintext.size() < 4) throw std::runtime_error("Decrypted payload too short.");
    uint32_t sigLen = 0;
    sigLen |= (static_cast<uint32_t>(decryptedPlaintext[0]) << 24);
    sigLen |= (static_cast<uint32_t>(decryptedPlaintext[1]) << 16);
    sigLen |= (static_cast<uint32_t>(decryptedPlaintext[2]) << 8);
    sigLen |= static_cast<uint32_t>(decryptedPlaintext[3]);

    if (decryptedPlaintext.size() < 4 + sigLen) throw std::runtime_error("Decrypted payload size mismatch.");
    
    CryptoModule::Bytes sigma(decryptedPlaintext.begin() + 4, decryptedPlaintext.begin() + 4 + sigLen);
    CryptoModule::Bytes dhpubU(decryptedPlaintext.begin() + 4 + sigLen, decryptedPlaintext.end());

    // ==========================================
    // 追踪 2：解密成功
    // ==========================================
    std::string auditMsg2 = "✅ AEAD 解密成功 (验证终端加密密钥合法)！\n\n";
    auditMsg2 += "【提取出终端临时公钥 dhpubU】:\n" + ToHex(dhpubU) + "\n\n";
    auditMsg2 += "【提取出终端 ECDSA 签名 sigma】:\n" + ToHex(sigma);
    BroadcastToMonitor("success", "🔓 2. tau 解密与数据分离", auditMsg2);

    // ==========================================
    // 追踪 3：验证签名
    // ==========================================
    CryptoModule::Bytes sigInput(resp.uid.begin(), resp.uid.end());
    sigInput.insert(sigInput.end(), session.tempDH.publicKey.begin(), session.tempDH.publicKey.end());
    sigInput.insert(sigInput.end(), dhpubU.begin(), dhpubU.end());
    sigInput.insert(sigInput.end(), resp.tagU.begin(), resp.tagU.end());

    if (!CryptoModule::VerifySignature(db_pkSig, sigInput, sigma)) {
        throw std::runtime_error("User signature verification failed! Illegal user.");
    }

    std::string auditMsg3 = "签名原文公式: uid || dhpubS || dhpubU || tagU\n\n";
    auditMsg3 += "💡 网关并不拥有用户私钥，而是提取注册时绑定的公钥进行非对称验签。\n\n";
    auditMsg3 += "【使用的验证公钥 pk_Sig】:\n" + ToHex(db_pkSig);
    BroadcastToMonitor("success", "✍️ 3. 终端 ECDSA 签名验证通过", auditMsg3);

    // ==========================================
    // 追踪 4：ECDH 共享秘密
    // ==========================================
    session.sharedSecret = CryptoModule::ComputeSharedSecret(session.tempDH.privateKey, dhpubU);
    BroadcastToMonitor("crypto", "🔑 4. 协商底层 ECDH 共享秘密", "公式: ECDH(网关临时私钥, 终端临时公钥 dhpubU)\n\n【计算出的 SharedSecret】:\n" + ToHex(session.sharedSecret));

    // ==========================================
    // 追踪 5：验证 tagU
    // ==========================================
    CryptoModule::Bytes expectedTagUInput = session.sharedSecret;
    expectedTagUInput.insert(expectedTagUInput.end(), resp.uid.begin(), resp.uid.end());
    expectedTagUInput.insert(expectedTagUInput.end(), session.tempDH.publicKey.begin(), session.tempDH.publicKey.end());
    expectedTagUInput.insert(expectedTagUInput.end(), session.serversigm.begin(), session.serversigm.end());
    expectedTagUInput.insert(expectedTagUInput.end(), dhpubU.begin(), dhpubU.end());
    std::string confirmStr = "clientconfirm";
    expectedTagUInput.insert(expectedTagUInput.end(), confirmStr.begin(), confirmStr.end());
    
    CryptoModule::Bytes expectedTagU = CryptoModule::Hash(expectedTagUInput);
    if (expectedTagU != resp.tagU) {
        throw std::runtime_error("TagU verification failed! Shared secret mismatch.");
    }

    std::string auditMsg4 = "tagU 组成部分:\n";
    auditMsg4 += "1. SharedSecret: " + ToHex(session.sharedSecret).substr(0, 16) + "...\n";
    auditMsg4 += "2. uid: " + resp.uid + "\n";
    auditMsg4 += "3. dhpubS: " + ToHex(session.tempDH.publicKey).substr(0, 16) + "...\n";
    auditMsg4 += "4. serversigm: " + ToHex(session.serversigm).substr(0, 16) + "...\n";
    auditMsg4 += "5. dhpubU: " + ToHex(dhpubU).substr(0, 16) + "...\n";
    auditMsg4 += "6. 常量: 'clientconfirm'\n\n";
    auditMsg4 += "网关本地计算出的 tagU:\n" + ToHex(expectedTagU) + "\n\n";
    auditMsg4 += "✅ 比对结果：与终端上传的 tagU 完美匹配！";
    BroadcastToMonitor("success", "✅ 5. 终端确认标签 tagU 匹配通过", auditMsg4);

    // 派生会话密钥
    CryptoModule::Bytes skInput = session.sharedSecret;
    skInput.insert(skInput.end(), session.tempDH.publicKey.begin(), session.tempDH.publicKey.end());
    skInput.insert(skInput.end(), session.serversigm.begin(), session.serversigm.end());
    skInput.insert(skInput.end(), dhpubU.begin(), dhpubU.end());
    std::string sessionStr = "sessionkey";
    skInput.insert(skInput.end(), sessionStr.begin(), sessionStr.end());
    
    session.sessionKey = CryptoModule::Hash(skInput);
    session.secureLayer.Initialize(session.sessionKey);

    // ==========================================
    // 追踪 6：网关确认参数签发
    // ==========================================
    CryptoModule::Bytes tagSInput = session.sharedSecret;
    tagSInput.insert(tagSInput.end(), resp.uid.begin(), resp.uid.end());
    tagSInput.insert(tagSInput.end(), resp.tau.begin(), resp.tau.end());
    tagSInput.insert(tagSInput.end(), session.tempDH.publicKey.begin(), session.tempDH.publicKey.end());
    tagSInput.insert(tagSInput.end(), resp.tagU.begin(), resp.tagU.end());
    std::string serverConfirmStr = "serverconfirm";
    tagSInput.insert(tagSInput.end(), serverConfirmStr.begin(), serverConfirmStr.end());
    
    confirmation.tagS = CryptoModule::Hash(tagSInput);
    confirmation.serversigtag = CryptoModule::Sign(m_longTermKeys.privateKey, confirmation.tagS);
    confirmation.success = true;

    std::string auditMsg5 = "tagS 组成部分:\n";
    auditMsg5 += "1. SharedSecret: " + ToHex(session.sharedSecret).substr(0, 16) + "...\n";
    auditMsg5 += "2. uid: " + resp.uid + "\n";
    auditMsg5 += "3. tau (密文): " + ToHex(resp.tau).substr(0, 16) + "...\n";
    auditMsg5 += "4. dhpubS: " + ToHex(session.tempDH.publicKey).substr(0, 16) + "...\n";
    auditMsg5 += "5. tagU: " + ToHex(resp.tagU).substr(0, 16) + "...\n";
    auditMsg5 += "6. 常量: 'serverconfirm'\n\n";
    auditMsg5 += "【生成网关确认标签 tagS】:\n" + ToHex(confirmation.tagS) + "\n\n";
    auditMsg5 += "【网关最终签名 serversigtag】:\n" + ToHex(confirmation.serversigtag);
    BroadcastToMonitor("crypto", "🏷️ 6. 签发网关反向确认参数", auditMsg5);

    return confirmation;
}

CryptoModule::Bytes Server::GetSessionKey(const std::string& uid) const {
    auto it = m_activeSessions.find(uid);
    if (it != m_activeSessions.end()) return it->second.sessionKey;
    return CryptoModule::Bytes();
}