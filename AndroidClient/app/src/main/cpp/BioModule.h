#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <tuple>

namespace BioModule {

    using Bytes = std::vector<uint8_t>;

    // 模糊提取器 Gen 函数的输出结构
    struct FuzzyExtractorData {
        Bytes R; // 提取出的高熵随机串 (用作密钥种子)
        Bytes P; // 辅助数据 (Helper Data，公开存储)
    };

    // ==========================================
    // 1. 模拟辅助工具 (用于替代真实的手机传感器)
    // ==========================================
    
    // 模拟录入一个全新的生物特征 (例如 64 字节的指纹特征)
    Bytes GenerateMockBiometric(size_t length = 64);
    
    // 模拟真实的指纹按压误差：向原始特征中随机注入指定数量的错误比特
    Bytes AddNoise(const Bytes& originalBio, int errorBitsCount);

    // ==========================================
    // 2. 模糊提取器核心逻辑 (Fuzzy Extractor)
    // ==========================================
    
    // 注册阶段调用：输入生物特征 bio，生成随机串 R 和辅助数据 P
    FuzzyExtractorData Gen(const Bytes& bio);
    
    // 认证阶段调用：输入带噪声的新特征 bio' 和辅助数据 P，尝试恢复 R
    // 如果差异超过阈值，返回空的 Bytes
    Bytes Rep(const Bytes& bio_prime, const Bytes& P);

} // namespace BioModule