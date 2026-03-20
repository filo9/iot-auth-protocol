#!/usr/bin/env python3
"""
S3: 模糊提取器 ROC/DET 曲线 + EER
第五章 — 生物特征安全性分析
数据来源: results/ 目录各方法真实测试数据
"""
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from scipy.interpolate import interp1d
import csv, os

BASE = '/home/filo/workspace/IoT_Auth_Protocol/results'

# ==========================================
# 已知固定测试点（来自 all_methods_comparison.txt）
# ==========================================
FIXED_POINTS = {
    'Method H\n(DINOv2+Hamming, SOCOfing)': {
        'tar': 96.98, 'far': 0.00,
        'genuine_total': 398, 'genuine_pass': 386,
        'impostor_total': 19900, 'impostor_pass': 0,
        'color': '#1a9850', 'marker': 'D', 'lw': 2.5,
    },
    'Method B\n(CLAHE+Gabor, SOCOfing)': {
        'tar': 87.29, 'far': 4.63,
        'genuine_total': 299, 'genuine_pass': 261,
        'impostor_total': 4950, 'impostor_pass': 229,
        'color': '#2196F3', 'marker': 's', 'lw': 2.0,
    },
    'Method A\n(ResNet34, SOCOfing)': {
        'tar': 84.28, 'far': 5.62,
        'genuine_total': 299, 'genuine_pass': 252,
        'impostor_total': 4950, 'impostor_pass': 278,
        'color': '#FF9800', 'marker': '^', 'lw': 2.0,
    },
    'Simulated\n(FVC2002)': {
        'tar': 94.29, 'far': 0.16,
        'genuine_total': 210, 'genuine_pass': 198,
        'impostor_total': 630, 'impostor_pass': 1,
        'color': '#9C27B0', 'marker': 'o', 'lw': 2.0,
    },
}

# ==========================================
# 从CSV读取ErrorBits分布，生成ROC曲线
# ==========================================
def load_scores(csv_path):
    genuine_errors, impostor_errors = [], []
    if not os.path.exists(csv_path):
        return None, None
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                eb = int(row['ErrorBits'])
                if row['Type'] == 'Genuine':
                    genuine_errors.append(eb)
                else:
                    impostor_errors.append(eb)
            except:
                pass
    return genuine_errors, impostor_errors

def compute_roc(genuine_errors, impostor_errors, max_thresh=30):
    thresholds = range(0, max_thresh + 1)
    tars, fars = [], []
    for t in thresholds:
        tar = sum(1 for e in genuine_errors if e <= t) / max(len(genuine_errors), 1) * 100
        far = sum(1 for e in impostor_errors if e <= t) / max(len(impostor_errors), 1) * 100
        tars.append(tar)
        fars.append(far)
    return np.array(fars), np.array(tars)

def find_eer(fars, tars):
    frrs = 100 - tars
    diffs = np.abs(fars - frrs)
    idx = np.argmin(diffs)
    return (fars[idx] + frrs[idx]) / 2, idx

# ==========================================
# 图1: ROC 曲线
# ==========================================
fig, axes = plt.subplots(1, 2, figsize=(14, 6))

ax_roc = axes[0]
ax_det = axes[1]

# 随机猜测基线
ax_roc.plot([0, 100], [0, 100], 'k--', lw=1, alpha=0.5, label='Random Guess')

csv_map = {
    'Method H\n(DINOv2+Hamming, SOCOfing)':
        f'{BASE}/soc_method_h_patch_hamming3/unified_test_plan_vault.csv',
    'Method B\n(CLAHE+Gabor, SOCOfing)':
        f'{BASE}/method_b_clahe_gabor_resnet/unified_test_plan_vault.csv',
    'Method A\n(ResNet34, SOCOfing)':
        f'{BASE}/method_a_resnet34/unified_test_plan_vault.csv',
}

eer_results = {}

for name, info in FIXED_POINTS.items():
    csv_path = csv_map.get(name)
    genuine_errors, impostor_errors = load_scores(csv_path) if csv_path else (None, None)

    if genuine_errors and len(genuine_errors) > 10:
        fars, tars = compute_roc(genuine_errors, impostor_errors)
        eer_val, eer_idx = find_eer(fars, tars)
        eer_results[name] = eer_val

        ax_roc.plot(fars, tars, color=info['color'], lw=info['lw'],
                    label=f"{name.split(chr(10))[0]} (EER={eer_val:.1f}%)")
        ax_roc.scatter([fars[eer_idx]], [tars[eer_idx]],
                       color=info['color'], s=80, zorder=5, marker=info['marker'])

        # DET曲线 (对数坐标)
        frrs = 100 - tars
        valid = (fars > 0) & (frrs > 0)
        if valid.sum() > 2:
            ax_det.plot(fars[valid], frrs[valid], color=info['color'], lw=info['lw'],
                        label=f"{name.split(chr(10))[0]}")
    else:
        # 用固定点画单点
        tar_val = info['tar']
        far_val = info['far']
        frr_val = 100 - tar_val
        eer_approx = (far_val + frr_val) / 2
        eer_results[name] = eer_approx

        ax_roc.scatter([far_val], [tar_val], color=info['color'],
                       s=120, zorder=5, marker=info['marker'],
                       label=f"{name.split(chr(10))[0]} (TAR={tar_val:.1f}%, FAR={far_val:.2f}%)")
        if far_val > 0 and frr_val > 0:
            ax_det.scatter([far_val], [frr_val], color=info['color'],
                           s=120, zorder=5, marker=info['marker'],
                           label=f"{name.split(chr(10))[0]}")

ax_roc.set_xlabel('False Acceptance Rate (FAR) %', fontsize=12)
ax_roc.set_ylabel('True Acceptance Rate (TAR) %', fontsize=12)
ax_roc.set_title('ROC Curve — Fuzzy Extractor Biometric Performance', fontsize=12, fontweight='bold')
ax_roc.legend(fontsize=9, loc='lower right')
ax_roc.set_xlim(-1, 20)
ax_roc.set_ylim(60, 101)
ax_roc.grid(True, alpha=0.3)
ax_roc.fill_between([0, 100], [0, 100], [100, 100], alpha=0.05, color='green')

# DET轴设置
ax_det.set_xscale('log')
ax_det.set_yscale('log')
ax_det.set_xlabel('False Acceptance Rate (FAR) %', fontsize=12)
ax_det.set_ylabel('False Rejection Rate (FRR) %', fontsize=12)
ax_det.set_title('DET Curve — Detection Error Tradeoff', fontsize=12, fontweight='bold')
ax_det.legend(fontsize=9)
ax_det.grid(True, alpha=0.3, which='both')
ax_det.set_xlim(0.001, 20)
ax_det.set_ylim(0.1, 50)

plt.tight_layout()
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_roc_det.pdf',
            dpi=300, bbox_inches='tight')
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_roc_det.png',
            dpi=300, bbox_inches='tight')
print("S3 done: fig5_roc_det.pdf/png")

# ==========================================
# 图2: 各方法 TAR/FAR 对比柱状图
# ==========================================
fig2, ax2 = plt.subplots(figsize=(10, 5))

method_names = [n.split('\n')[0] for n in FIXED_POINTS.keys()]
tar_vals = [FIXED_POINTS[n]['tar'] for n in FIXED_POINTS]
far_vals = [FIXED_POINTS[n]['far'] for n in FIXED_POINTS]
colors_list = [FIXED_POINTS[n]['color'] for n in FIXED_POINTS]

x = np.arange(len(method_names))
w = 0.35

bars1 = ax2.bar(x - w/2, tar_vals, w, label='TAR (%)', color=colors_list, alpha=0.85, edgecolor='black', lw=0.8)
bars2 = ax2.bar(x + w/2, far_vals, w, label='FAR (%)', color=colors_list, alpha=0.4,
                edgecolor='black', lw=0.8, hatch='//')

for bar, val in zip(bars1, tar_vals):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
             f'{val:.1f}%', ha='center', va='bottom', fontsize=9, fontweight='bold')
for bar, val in zip(bars2, far_vals):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
             f'{val:.2f}%', ha='center', va='bottom', fontsize=9)

ax2.axhline(y=90, color='green', linestyle='--', alpha=0.6, label='TAR Target (90%)')
ax2.axhline(y=5, color='red', linestyle='--', alpha=0.6, label='FAR Threshold (5%)')
ax2.set_xticks(x)
ax2.set_xticklabels(method_names, fontsize=10)
ax2.set_ylabel('Rate (%)', fontsize=12)
ax2.set_title('Biometric Recognition Performance Comparison\n(TAR vs FAR across Methods and Datasets)',
              fontsize=12, fontweight='bold')
ax2.legend(fontsize=10)
ax2.set_ylim(0, 110)
ax2.grid(True, axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_tar_far_comparison.pdf',
            dpi=300, bbox_inches='tight')
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_tar_far_comparison.png',
            dpi=300, bbox_inches='tight')
print("S3 done: fig5_tar_far_comparison.pdf/png")
