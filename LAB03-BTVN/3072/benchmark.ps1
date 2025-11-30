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
$resultFile = "all_time_results.txt"

# Xóa file cũ nếu tồn tại
if (Test-Path $resultFile) { Remove-Item $resultFile }

Add-Content -Path $resultFile -Value "=== RSA Benchmark Results (Total Time 1000 runs in ms) ===`n"

foreach ($file in $files) {

    Write-Host ""
    Write-Host "============================================="
    Write-Host "Benchmark for file: $file"
    Write-Host "============================================="

    $cmd = ".\RSA.exe --encrypt --pub .\pub3072.pem --in $file --encode hex --out hello.bin"
    $totalUs = 0

    for ($i = 1; $i -le $iterations; $i++) {

        $output = Invoke-Expression $cmd

        if ($output -match '\[Time\]:\s*(\d+)\s*us') {
            $us = [int]$matches[1]
            $totalUs += $us
            Write-Host "Run {$i}:`t $us us"
        } else {
            Write-Host "Run {$i}:`t Không tìm thấy time!"
        }
    }

    # Tổng thời gian microseconds -> milliseconds
    $totalMs = $totalUs / 1000.0

    # Lấy tên file: 1KB, 4MB...
    $sizeName = (Split-Path $file -Leaf).Replace(".bin","")

    # Dòng lưu file
    $line = "{$sizeName}: $totalMs ms"

    Add-Content -Path $resultFile -Value $line

    Write-Host ">> Tổng thời gian 1000 lần cho {$sizeName}: $totalMs ms"
}

Write-Host "`n==== DONE ===="
Write-Host "Kết quả lưu tại: $resultFile"
