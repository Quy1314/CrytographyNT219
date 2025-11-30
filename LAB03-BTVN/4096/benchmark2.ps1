$files = @(
    "..\6TESTFile\1KB.bin",
    "..\6TESTFile\4KB.bin",
    "..\6TESTFile\16KB.bin",
    "..\6TESTFile\256KB.bin",
    "..\6TESTFile\1MB.bin",
    "..\6TESTFile\4MB.bin",
    "..\6TESTFile\8MB.bin"
)

$iterations = 1000
$resultFile = "all_time_results_encrypt_decrypt.txt"

# Xóa file cũ nếu tồn tại
if (Test-Path $resultFile) { Remove-Item $resultFile }

Add-Content -Path $resultFile -Value "=== RSA Benchmark Results (Total Time 1000 runs in ms) ===`n"

foreach ($file in $files) {

    Write-Host ""
    Write-Host "============================================="
    Write-Host "Benchmark for file: $file"
    Write-Host "============================================="

    $sizeName = (Split-Path $file -Leaf).Replace(".bin","")

    $totalEncryptUs = 0
    $totalDecryptUs = 0

    $encryptCmd = ".\RSA.exe --encrypt --in $file --pub .\pub4096.pem --encode hex --out output.bin"
    $decryptCmd = ".\RSA.exe --decrypt --in output.bin --priv .\prv4096.pem --encode hex"

    Write-Host "> Benchmarking Encrypt & Decrypt alternately..."

    for ($i = 1; $i -le $iterations; $i++) {

        # Encrypt
        $outputEnc = Invoke-Expression $encryptCmd
        if ($outputEnc -match '\[Time\]:\s*(\d+)\s*us') {
            $us = [int]$matches[1]
            $totalEncryptUs += $us
        } else {
            Write-Host "Run {$i} Encrypt: Không tìm thấy time!"
        }
        Start-Sleep -Milliseconds 100

        # Decrypt
        $outputDec = Invoke-Expression $decryptCmd
        if ($outputDec -match '\[Time\]:\s*(\d+)\s*us') {
            $us = [int]$matches[1]
            $totalDecryptUs += $us
        } else {
            Write-Host "Run {$i} Decrypt: Không tìm thấy time!"
        }

        # Tuỳ chọn: hiển thị tiến trình mỗi 50 runs
        if ($i % 50 -eq 0) {
            Write-Host "Run $i / $iterations completed..."
        }
    }

    $totalEncryptMs = $totalEncryptUs / 1000.0
    $totalDecryptMs = $totalDecryptUs / 1000.0

    # Ghi file
    $line = "{$sizeName}: Encrypt = $totalEncryptMs ms, Decrypt = $totalDecryptMs ms"
    Add-Content -Path $resultFile -Value $line

    Write-Host ">> Tổng thời gian Encrypt 1000 lần cho {$sizeName}: $totalEncryptMs ms"
    Write-Host ">> Tổng thời gian Decrypt 1000 lần cho {$sizeName}: $totalDecryptMs ms"
    Write-Host ">> Dừng 3 giây trước khi benchmark file tiếp theo..."
    Start-Sleep -Seconds 3
}

Write-Host "`n==== DONE ===="
Write-Host "Kết quả lưu tại: $resultFile"
