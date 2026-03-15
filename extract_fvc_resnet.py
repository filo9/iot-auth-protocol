import os
import torch
import torchvision.models as models
import torchvision.transforms as transforms
import torch.nn.functional as F
from PIL import Image, ImageOps
import numpy as np
import csv

# 图像对比度增强
class AutoContrast:
    def __call__(self, img):
        return ImageOps.autocontrast(img)

INPUT_DIR = "./fvc2002_db1"  
OUTPUT_DIR = "./fingerprint_features"
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("🧠 启动半实物仿真引擎：加载 ResNet-34 提取真实基准...")

# 加载本地缓存的 ResNet-34
model = models.resnet34(weights=models.ResNet34_Weights.IMAGENET1K_V1)
model.fc = torch.nn.Identity() 
model.eval() 

transform = transforms.Compose([
    AutoContrast(),                     
    transforms.CenterCrop((300, 300)),  
    transforms.Resize((224, 224)),      
    transforms.Grayscale(num_output_channels=3), 
    transforms.ToTensor(),              
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]) 
])

mapped_users = [str(i) for i in range(101, 111)] 
samples = range(1, 8)  # 每个用户生成 1 份基准 + 6 份带噪声的探针 = 7 份

# =========================================================
# 🎛️ 物理噪声旋钮 (Noise Sigma)
# 0.20 = 高质量指纹传感器（指纹清晰，微小形变）
# 0.35 = 日常使用场景（存在部分脱皮或轻微滑移）
# 0.50 = 恶劣环境（大量汗液、手指干裂） -> 测试 RS(32,12) 的极限
# =========================================================
NOISE_SIGMA = 0.01 

processed_files = 0
np.random.seed(42) # 固定噪声种子，确保你的实验结果可复现

print(f"🔬 开始读取 10 个真实物理指纹，并衍生受控噪声数据...")

with torch.no_grad(): 
    for u in mapped_users:
        # 1. 提取真实的物理指纹作为绝对基准 (Template)
        base_img_path = os.path.join(INPUT_DIR, f"{u}_1.tif")
        if not os.path.exists(base_img_path): 
            print(f"⚠️ 找不到基准图片 {base_img_path}，跳过该用户。")
            continue

        img = Image.open(base_img_path)
        input_tensor = transform(img).unsqueeze(0) 
        
        # 提取 512 维特征并进行 L2 超球面投射
        base_features = model(input_tensor)
        base_features = F.normalize(base_features, p=2, dim=1)
        base_features = base_features.squeeze().numpy()
        
        # 零均值化，锁定 C++ 中的二值化象限
        base_features = base_features - np.mean(base_features)

        # 2. 生成 7 份数据
        for i in samples:
            if i == 1:
                # 第 1 份：纯净的真实物理特征
                feat = base_features
            else:
                # 第 2~7 份：注入高斯白噪声模拟环境干扰
                noise = np.random.randn(512).astype(np.float32) * NOISE_SIGMA
                feat = base_features + noise
                # 重新计算均值，防止噪声使整体特征发生象限偏移
                feat = feat - np.mean(feat) 

            with open(os.path.join(OUTPUT_DIR, f"{u}_{i}_vault.dat"), "wb") as f:
                f.write(feat.astype(np.float32).tobytes())
            
            processed_files += 1

print(f"✅ 半实物仿真提取完毕！共生成 {processed_files} 份混合特征 (噪声水平: {NOISE_SIGMA})。")

# 生成压测专用的 CSV 计划表 (适配了 7 次采样的循环逻辑)
test_plan_vault = []
for u in mapped_users:
    for i in samples:
        for j in range(i + 1, 8):
            test_plan_vault.append(["Genuine", f"{u}_{i}_vault", f"{u}_{j}_vault", 0])
for u1 in mapped_users:
    for i in samples:
        for u2 in mapped_users:
            if u1 == u2: continue
            test_plan_vault.append(["Impostor", f"{u1}_{i}_vault", f"{u2}_1_vault", 0])

with open("unified_test_plan_vault.csv", "w", newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["Type", "Template", "Probe", "ErrorBits"])
    writer.writerows(test_plan_vault)
print("👉 下一步：直接去 build 目录执行 ./test_batch_vault！")