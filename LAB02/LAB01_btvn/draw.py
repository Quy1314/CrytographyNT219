import matplotlib.pyplot as plt
import numpy as np

# === DỮ LIỆU CBC (ms) ===
sizes = ["1KB", "4KB", "16KB", "256KB", "1MB", "4MB", "8MB"]

# Windows
cbc_encrypt_win = [410, 540, 820, 6600, 25500, 94500, 193000]
cbc_decrypt_win = [460, 590, 870, 6850, 26300, 95800, 195500]

# Ubuntu
cbc_encrypt_linux = [4.0, 4.3, 4.8, 5.4, 6.1, 6.9, 7.7]
cbc_decrypt_linux = [3.7, 4.1, 4.5, 5.1, 5.8, 6.5, 7.3]

# === VẼ HAI SUBPLOT (Encrypt & Decrypt) ===
fig, axes = plt.subplots(2, 1, figsize=(9, 8), sharex=True)

# --- ENCRYPT ---
axes[0].plot(sizes, cbc_encrypt_win, marker='o', color='royalblue', linewidth=2, label="Windows")
axes[0].plot(sizes, cbc_encrypt_linux, marker='s', color='seagreen', linewidth=2, label="Ubuntu")
axes[0].set_title("AES-CBC Encrypt: Windows vs Ubuntu", fontsize=13, weight="bold")
axes[0].set_ylabel("Thời gian (ms)", fontsize=11)
axes[0].set_yscale("log")  # dùng log scale cho dễ nhìn
axes[0].grid(True, linestyle="--", alpha=0.6)
axes[0].legend()

# --- DECRYPT ---
axes[1].plot(sizes, cbc_decrypt_win, marker='o', color='darkorange', linewidth=2, label="Windows")
axes[1].plot(sizes, cbc_decrypt_linux, marker='s', color='mediumvioletred', linewidth=2, label="Ubuntu")
axes[1].set_title("AES-CBC Decrypt: Windows vs Ubuntu", fontsize=13, weight="bold")
axes[1].set_xlabel("Kích thước file", fontsize=11)
axes[1].set_ylabel("Thời gian (ms)", fontsize=11)
axes[1].set_yscale("log")
axes[1].grid(True, linestyle="--", alpha=0.6)
axes[1].legend()

# --- TIÊU ĐỀ TỔNG ---
plt.suptitle("So sánh thời gian thực thi AES-CBC giữa Windows và Ubuntu (log scale)", fontsize=14, weight="bold")
plt.tight_layout(rect=[0, 0, 1, 0.96])
plt.show()
