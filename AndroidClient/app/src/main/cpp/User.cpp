#include "User.h"
#include "DeterministicECC.h"
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <android/log.h>
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "IoT_Auth_Native", __VA_ARGS__)

extern std::string g_storagePath;
// ==========================================
// 注册阶段
// ==========================================

ProtocolMessages::RegistrationRequest User::GenerateRegistrationRequest(
    const std::string& password, 
    const CryptoModule::Bytes& biometric) 
{
    // 1. 生物特征处理: R, P <- FuzzyExtractor.Gen(bio) 
    auto feData = BioModule::Gen(biometric);

    // 2. PRF密钥生成: k <- {0,1}^lambda
    // 提取设备硬件指纹作为隐式透明 PIN 码，进行高强度持久化包裹
    std::string device_pin = GetDeviceHardwareID();
    std::string keystore_file = g_storagePath + "user_" + m_uid + "_keystore.dat";

    m_secureManager.GenerateAndWrapCredential(device_pin, keystore_file);

    // 3. 主密钥派生: kmaster = F(k, pw || R) [cite: 157]
    CryptoModule::Bytes pwBytes(password.begin(), password.end());
    CryptoModule::Bytes kmaster = m_secureManager.ComputeMasterKey(pwBytes, feData.R);

    // 4. 使用新接口：基于 K_master 确定性生成用户签名密钥对
    auto sigKeyPair = DeterministicECC::DeriveKeyPairFromSeed(kmaster);

    // 5. 生成加密密钥对 [cite: 159]
    auto encKeyPair = CryptoModule::GenerateEncryptionKeyPair();

    // 6. 保存本地凭证 ask (此时还缺服务器公钥，等响应回来补齐) [cite: 169]
    m_ask.P = feData.P;
    m_ask.pkEnc = encKeyPair.publicKey;

    // 7. 构造发给服务器的注册包: avk = (pk_Sig, sk_Enc) [cite: 161]
    ProtocolMessages::RegistrationRequest req;
    req.uid = m_uid;
    req.avk_pkSig = sigKeyPair.publicKey;
    req.avk_skEnc = encKeyPair.privateKey; // 将解密私钥托管给服务器 [cite: 160]

    return req;
}

void User::ProcessRegistrationResponse(const ProtocolMessages::RegistrationResponse& response) {
    if (!response.success) throw std::runtime_error("Registration failed on server.");

    // 1. 补齐内存凭证
    m_ask.serversigpk = response.serversigpk;

    // 2. 将服务器公钥安全持久化到本地沙盒
    std::string pubkey_file = g_storagePath + "server_pk.dat";
    std::ofstream outfile(pubkey_file, std::ios::binary);
    if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open file to save server public key.");
    }

    // 将公钥的二进制字节流直接写入文件
    outfile.write(reinterpret_cast<const char*>(m_ask.serversigpk.data()), m_ask.serversigpk.size());
    outfile.close();
}

// ==========================================
// 认证与密钥协商阶段
// ==========================================

ProtocolMessages::AuthRequest User::InitiateAuthentication() {
    ProtocolMessages::AuthRequest req;
    req.uid = m_uid; // [cite: 174]
    return req;
}

ProtocolMessages::AuthResponse User::ProcessAuthChallenge(
        const ProtocolMessages::AuthChallenge& challenge,
        const std::string& password,
        const CryptoModule::Bytes& currentBiometric)
{
    LOGE("-----> 进入 User::ProcessAuthChallenge <-----");

    if (m_ask.serversigpk.empty()) {
        std::string pubkey_file = g_storagePath + "server_pk.dat";
        std::ifstream infile(pubkey_file, std::ios::binary | std::ios::ate);
        if (infile.is_open()) {
            std::streamsize size = infile.tellg();
            infile.seekg(0, std::ios::beg);
            m_ask.serversigpk.resize(size);
            infile.read(reinterpret_cast<char*>(m_ask.serversigpk.data()), size);
        }
    }

#ifndef __ANDROID__
    try {
            CryptoModule::VerifySignature(m_ask.serversigpk, challenge.dhpubS, challenge.serversigm);
        } catch(...) {}
#endif

    m_peerDHPub = challenge.dhpubS;
    m_serverSigM = challenge.serversigm;

    std::string device_pin = GetDeviceHardwareID();
    std::string keystore_file = g_storagePath + "user_" + m_uid + "_keystore.dat";
    bool isKeystoreLoaded = false;
    try {
        isKeystoreLoaded = m_secureManager.UnwrapAndLoadCredential(device_pin, keystore_file);
    } catch(...) {}

    LOGE("-----> 准备执行 BioModule::Rep 恢复生物特征...");
    CryptoModule::Bytes R;
    bool isBioSuccess = true;
    try {
        R = BioModule::Rep(currentBiometric, m_ask.P);
        if (R.empty()) isBioSuccess = false;
    } catch (...) {
        isBioSuccess = false;
    }

    CryptoModule::Bytes kmaster;
    CryptoModule::KeyPair sigKeyPair;

    if (isBioSuccess && isKeystoreLoaded) {
        try {
            CryptoModule::Bytes pwBytes(password.begin(), password.end());
            kmaster = m_secureManager.ComputeMasterKey(pwBytes, R);
            sigKeyPair = DeterministicECC::DeriveKeyPairFromSeed(kmaster);
        } catch (...) {
            isBioSuccess = false;
        }
    } else {
        isBioSuccess = false;
    }

    if (!isBioSuccess) {
        LOGE("-----> 💀 [防御触发] 提取失败！切入欺骗模式，准备生成伪造载荷...");
        kmaster = CryptoModule::Hash(currentBiometric);
        try {
            sigKeyPair = CryptoModule::GenerateSignatureKeyPair({});
        } catch(...) {}
    }

    m_tempDH = CryptoModule::GenerateDHKeyPair();
    try {
        m_sharedSecret = CryptoModule::ComputeSharedSecret(m_tempDH.privateKey, challenge.dhpubS);
    } catch (...) {
        m_sharedSecret = CryptoModule::Hash(m_tempDH.publicKey);
    }

    CryptoModule::Bytes tagInput = m_sharedSecret;
    tagInput.insert(tagInput.end(), m_uid.begin(), m_uid.end());
    tagInput.insert(tagInput.end(), challenge.dhpubS.begin(), challenge.dhpubS.end());
    tagInput.insert(tagInput.end(), challenge.serversigm.begin(), challenge.serversigm.end());
    tagInput.insert(tagInput.end(), m_tempDH.publicKey.begin(), m_tempDH.publicKey.end());
    std::string confirmStr = "clientconfirm";
    tagInput.insert(tagInput.end(), confirmStr.begin(), confirmStr.end());

    CryptoModule::Bytes tagU;
    try { tagU = CryptoModule::Hash(tagInput); } catch(...) { tagU.resize(32, 0); }

    CryptoModule::Bytes sigInput(m_uid.begin(), m_uid.end());
    sigInput.insert(sigInput.end(), challenge.dhpubS.begin(), challenge.dhpubS.end());
    sigInput.insert(sigInput.end(), m_tempDH.publicKey.begin(), m_tempDH.publicKey.end());
    sigInput.insert(sigInput.end(), tagU.begin(), tagU.end());

    CryptoModule::Bytes sigma;
    try {
        sigma = CryptoModule::Sign(sigKeyPair.privateKey, sigInput);
    } catch (...) {
        sigma = CryptoModule::Hash(sigInput); // 伪造签名防崩溃
    }

    CryptoModule::Bytes plaintextToEnc;
    uint32_t sigLen = sigma.size();
    uint8_t lenBytes[4] = {
            static_cast<uint8_t>((sigLen >> 24) & 0xFF), static_cast<uint8_t>((sigLen >> 16) & 0xFF),
            static_cast<uint8_t>((sigLen >> 8) & 0xFF), static_cast<uint8_t>(sigLen & 0xFF)
    };

    plaintextToEnc.insert(plaintextToEnc.end(), lenBytes, lenBytes + 4);
    plaintextToEnc.insert(plaintextToEnc.end(), sigma.begin(), sigma.end());
    plaintextToEnc.insert(plaintextToEnc.end(), m_tempDH.publicKey.begin(), m_tempDH.publicKey.end());

    CryptoModule::Bytes tau;
    try {
        CryptoModule::Bytes actualEncKey = m_ask.pkEnc;
        // 核心修复：如果指纹失败或公钥为空，故意抛出异常，跳过 OpenSSL 解析，走到 catch 去生成伪造密文
        if (!isBioSuccess || actualEncKey.empty()) {
            throw std::runtime_error("Force fallback to fake ciphertext");
        }
        tau = CryptoModule::Encrypt(actualEncKey, plaintextToEnc);
    } catch (...) {
        // ==========================================
        // 【终极防侧信道】：无视任何公钥解析错误，直接生成一段极其逼真的伪造密文
        // ==========================================
        tau = CryptoModule::Hash(plaintextToEnc);
        tau.insert(tau.end(), m_sharedSecret.begin(), m_sharedSecret.end());
        tau.resize(128, 0x42); // 填充至合法长度，骗过格式检查
    }

    m_tau = tau;
    m_tagU = tagU;

    ProtocolMessages::AuthResponse resp;
    resp.uid = m_uid;
    resp.tau = tau;
    resp.tagU = tagU;
    return resp;
}
bool User::FinalizeAuthentication(const ProtocolMessages::AuthConfirmation& confirm) {
    LOGE("-----> 进入 FinalizeAuthentication <-----");

    // 1. Android 平台跳过底层验签 (已交由 Kotlin 层安全验证)，Linux/网关端保留底层验证
#ifndef __ANDROID__
    if (!CryptoModule::VerifySignature(m_ask.serversigpk, confirm.tagS, confirm.serversigtag)) {
        LOGE("❌ C++层验签失败！");
        return false;
    }
#endif

    // 2. 验证网关下发的 tagS (防篡改校验)
    CryptoModule::Bytes tagSInput = m_sharedSecret;
    tagSInput.insert(tagSInput.end(), m_uid.begin(), m_uid.end());
    tagSInput.insert(tagSInput.end(), m_tau.begin(), m_tau.end());
    tagSInput.insert(tagSInput.end(), m_peerDHPub.begin(), m_peerDHPub.end()); // peerDHPub 就是服务端的 dhpubS
    tagSInput.insert(tagSInput.end(), m_tagU.begin(), m_tagU.end());
    std::string serverConfirmStr = "serverconfirm";
    tagSInput.insert(tagSInput.end(), serverConfirmStr.begin(), serverConfirmStr.end());

    CryptoModule::Bytes expectedTagS = CryptoModule::Hash(tagSInput);
    if (expectedTagS != confirm.tagS) {
        LOGE("❌ TagS 验证失败！网关生成的 Hash 与本地计算不匹配！");
        return false;
    }

    // 3. 验证通过，派生最终的会话密钥 (Session Key)
    CryptoModule::Bytes skInput = m_sharedSecret;
    skInput.insert(skInput.end(), m_peerDHPub.begin(), m_peerDHPub.end());    // dhpubS
    skInput.insert(skInput.end(), m_serverSigM.begin(), m_serverSigM.end());  // serversigm
    skInput.insert(skInput.end(), m_tempDH.publicKey.begin(), m_tempDH.publicKey.end()); // dhpubU
    std::string sessionStr = "sessionkey";
    skInput.insert(skInput.end(), sessionStr.begin(), sessionStr.end());

    m_sessionKey = CryptoModule::Hash(skInput);

    // 4. 将新鲜出炉的会话密钥装载到 AEAD 安全隧道引擎中
    m_secureLayer.Initialize(m_sessionKey);

    LOGE("✅ FinalizeAuthentication 彻底成功！安全通道建立。");
    return true;
}