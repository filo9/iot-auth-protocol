#include "BioModule.h"
#include "ReedSolomon.h"
#include <random>
#include <stdexcept>
#include <iostream>
#include <openssl/sha.h> 

namespace BioModule {

    // ---------------------------------------------------------
    // 模拟器：生成假指纹和注入噪声 (保持不变)
    // ---------------------------------------------------------
    Bytes GenerateMockBiometric(size_t length) {
        Bytes bio(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(0, 255);
        for (size_t i = 0; i < length; ++i) {
            bio[i] = static_cast<uint8_t>(dis(gen));
        }
        return bio;
    }

    Bytes AddNoise(const Bytes& originalBio, int errorBitsCount) {
        Bytes noisyBio = originalBio;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> byteDis(0, noisyBio.size() - 1);
        std::uniform_int_distribution<int> bitDis(0, 7);

        for (int i = 0; i < errorBitsCount; ++i) {
            noisyBio[byteDis(gen)] ^= (1 << bitDis(gen));
        }
        return noisyBio;
    }

    // 实例化全局编解码器: n=64, k=32 (最高纠错16字节)
    static RS::ReedSolomonCodec rsCodec(64, 32); 

    FuzzyExtractorData Gen(const Bytes& bio) {
        if (bio.size() != 64) throw std::runtime_error("Biometric must be 64 bytes");
        FuzzyExtractorData data;
        
        // 1. 生成 32 字节高熵密钥 K
        Bytes K = GenerateMockBiometric(32);

        // 2. 利用真正的 RS 引擎将 32 字节 K 编码为 64 字节码字 C
        Bytes C = rsCodec.Encode(K);

        // 3. 构建安全草图 P = C XOR bio
        data.P.resize(64);
        for (size_t i = 0; i < 64; ++i) {
            data.P[i] = C[i] ^ bio[i];
        }

        // 4. 隐私放大 R = SHA256(K)
        data.R.resize(SHA256_DIGEST_LENGTH);
        SHA256(K.data(), K.size(), data.R.data());

        return data;
    }

    Bytes Rep(const Bytes& bio_prime, const Bytes& P) {
        if (bio_prime.size() != 64 || P.size() != 64) return Bytes();

        // 1. 消除生物特征偏差 C' = P XOR bio_prime
        Bytes C_prime(64);
        for (size_t i = 0; i < 64; ++i) {
            C_prime[i] = P[i] ^ bio_prime[i];
        }

        // 2. 利用真正的 RS 引擎进行深层代数纠错
        bool uncorrectable = false;
        Bytes K_recovered = rsCodec.Decode(C_prime, uncorrectable);

        if (uncorrectable) {
            std::cout << "[物理防御拦截] RS(64,32) 报告超出纠错极限 (突发损坏 > 25%)！\n";
            return Bytes();
        }

        // 3. 隐私放大
        Bytes R_recovered(SHA256_DIGEST_LENGTH);
        SHA256(K_recovered.data(), K_recovered.size(), R_recovered.data());

        return R_recovered;
    }

} // namespace BioModule