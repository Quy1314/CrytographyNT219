import matplotlib.pyplot as plt
import numpy as np

# Thuật toán
algorithms = ["SHA-224", "SHA-256", "SHA-384", "SHA-512",
              "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
              "SHAKE128", "SHAKE256"]

# Các file benchmark
files = ["1MB", "10MB", "100MB"]
x = np.arange(len(files))

# Throughput (MB/s)
throughput = np.array([
    [2160.72, 2136.24, 1814.07],  # SHA-224
    [2163.37, 2144.47, 1823.21],  # SHA-256
    [683.13, 621.19, 604.95],     # SHA-384
    [708.49, 563.16, 602.00],     # SHA-512
    [607.72, 521.34, 506.40],     # SHA3-224
    [572.65, 470.62, 508.53],     # SHA3-256
    [432.29, 372.34, 375.96],     # SHA3-384
    [297.75, 254.11, 274.56],     # SHA3-512
    [701.45, 594.67, 611.44],     # SHAKE128
    [574.52, 482.32, 481.02]      # SHAKE256
])

# Vẽ biểu đồ
plt.figure(figsize=(14,7))
for i, algo in enumerate(algorithms):
    plt.plot(x, throughput[i], marker='o', label=algo)

plt.title("Benchmark Hash - Throughput (MB/s)")
plt.xlabel("File size")
plt.ylabel("Throughput (MB/s)")
plt.xticks(x, files)
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend(fontsize=9)
plt.tight_layout()
plt.show()
