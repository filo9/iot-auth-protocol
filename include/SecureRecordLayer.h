#ifndef SECURE_RECORD_LAYER_H
#define SECURE_RECORD_LAYER_H

#include "CryptoModule.h"
#include <string>
#include <vector>
#include <cstdint>

// 安全记录层：负责握手后的对称加密业务通信 (采用 ChaCha20-Poly1305)
class SecureRecordLayer {
private:
    CryptoModule::Bytes m_sessionKey;
    uint32_t m_sendSeq; // 发送方序列号 (单调递增)
    uint32_t m_recvSeq; // 接收方高水位序列号 (防重放攻击)

    // 内部常量配置
    static const int CHACHA20_KEY_LEN = 32;
    static const int CHACHA20_IV_LEN = 12;
    static const int POLY1305_TAG_LEN = 16;

    // 辅助函数：将 32 位序列号构造为 RFC 7539 兼容的 96 位 (12字节) Nonce
    CryptoModule::Bytes ConstructNonce(uint32_t seq);

public:
    SecureRecordLayer();
    
    // 握手成功后注入会话密钥
    void Initialize(const CryptoModule::Bytes& sessionKey);

    // 封装并加密业务指令 (生成跨平台的 TLV 二进制流)
    // 格式: [4字节Payload长度] || [12字节Nonce] || [16字节Tag] || [密文Payload]
    CryptoModule::Bytes ProtectRecord(const std::string& plaintextCommand);

    // 解包、验证并解密业务指令 (自动拦截重放攻击)
    std::string UnprotectRecord(const CryptoModule::Bytes& securePacket);
};

#endif // SECURE_RECORD_LAYER_H