#ifndef SECURE_CREDENTIAL_MANAGER_H
#define SECURE_CREDENTIAL_MANAGER_H

#include "CryptoModule.h"
#include <string>
#include <vector>

class SecureCredentialManager {
private:
    // 核心机密：高熵本地凭证 k (模拟存放在 TEE 的安全内存中)
    CryptoModule::Bytes m_secure_k;
    bool m_is_unlocked = false;

    // 内部常量配置
    static const int PBKDF2_ITERATIONS = 100000; // 抵抗离线字典攻击的迭代次数
    static const int KEK_LENGTH = 16;            // AES-128 需要 16 字节的 KEK
    static const int SALT_LENGTH = 16;           // 随机盐长度
    static const int IV_LENGTH = 12;             // GCM 标准 IV 长度
    static const int TAG_LENGTH = 16;            // GCM 认证标签长度

public:
    SecureCredentialManager() = default;
    ~SecureCredentialManager(); // 析构时必须安全擦除内存

    // ==========================================
    // 阶段一：设备注册/初始化 (在安全区生成 k 并加密持久化)
    // ==========================================
    // pin: 用户设置的本地保护密码 (例如 6 位数字)
    // filepath: 本地存储路径 (例如 "keystore.dat")
    void GenerateAndWrapCredential(const std::string& pin, const std::string& filepath);

    // ==========================================
    // 阶段二：设备重启/认证唤醒 (输入 PIN 解锁 k 到安全内存)
    // ==========================================
    bool UnwrapAndLoadCredential(const std::string& pin, const std::string& filepath);

    // ==========================================
    // 阶段三：安全域内计算 (外界无法获取 k，只能委托 TEE 计算)
    // ==========================================
    // 严格遵循论文公式：kmaster = PRF(k, pw || R)
    CryptoModule::Bytes ComputeMasterKey(const CryptoModule::Bytes& pw, const CryptoModule::Bytes& feData_R);

    bool IsUnlocked() const { return m_is_unlocked; }
};

#endif // SECURE_CREDENTIAL_MANAGER_H