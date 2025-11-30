import matplotlib.pyplot as plt
import numpy as np

# Thuật toán
algorithms = ["SHA-224", "SHA-256", "SHA-384", "SHA-512",
              "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
              "SHAKE128", "SHAKE256"]

# Các file benchmark
files = ["1MB", "10MB", "100MB"]
x = np.arange(len(files))

# Thời gian trung bình (s/run)
data = np.array([
    [0.000463, 0.004681, 0.055125],  # SHA-224
    [0.000462, 0.004663, 0.054848],  # SHA-256
    [0.001464, 0.016098, 0.165303],  # SHA-384
    [0.001411, 0.017757, 0.166112],  # SHA-512
    [0.001646, 0.019181, 0.197472],  # SHA3-224
    [0.001746, 0.021248, 0.196644],  # SHA3-256
    [0.002313, 0.026857, 0.265988],  # SHA3-384
    [0.003359, 0.039353, 0.364218],  # SHA3-512
    [0.001426, 0.016816, 0.163549],  # SHAKE128
    [0.001741, 0.020733, 0.207892]   # SHAKE256
])

# Vẽ biểu đồ
plt.figure(figsize=(14,7))
for i, algo in enumerate(algorithms):
    plt.plot(x, data[i], marker='o', label=algo)

plt.title("Benchmark Hash - Thời gian trung bình mỗi lần (s/run)")
plt.xlabel("File size")
plt.ylabel("Avg Time (s)")
plt.xticks(x, files)
plt.yscale("log")  # dùng log để dễ so sánh thời gian
plt.grid(True, which='both', linestyle='--', alpha=0.5)
plt.legend(fontsize=9)
plt.tight_layout()
plt.show()
