# ====== CẤU HÌNH (DECRYPT) ======
$N = 1000                                  # Số lần chạy (mỗi lần lớn)
$TotalSets = 10                            # Tổng số "lần lớn"
$logFile = "CBC_4KB_decrypt_log.txt"       # File ghi log
$inputFile = "benchmark_output\4KB_CBC_out.bin"                 # Input là file đã mã hóa
$outputFile = "benchmark_output\4KB_CBC_decrypted.txt"          # Output là file đã giải mã
$mode = "CBC"                              # Phải giống với khi mã hóa
$keylen = 128                              # Độ dài khóa
$threads = 16                              # Số luồng chạy

$keyHex = "00112233445566778899AABBCCDDEEFF"
$ivOrNonceHex = "AABBCCDDEEFF00112233445566778899"
# ======================

# Xóa log cũ nếu có
if (Test-Path $logFile) { Remove-Item $logFile }

# Biến tổng
$grandTotalTimeMs = 0
$totalRuns = $N * $TotalSets

Write-Host "Bắt đầu benchmark $TotalSets lần (mỗi lần $N lặp, tổng cộng $totalRuns lặp)..."
Write-Host "Chế độ: DECRYPT $mode"
Write-Host "Input: $inputFile"
Write-Host "Threads: $threads"
Write-Host "----------------------------------------"

# --- VÒNG LẶP LỚN ---
for ($j = 1; $j -le $TotalSets; $j++) {
    Write-Host "Bắt đầu Lần chạy Lớn $j / $TotalSets..."
    
    $setTimeMs = 0

    # --- VÒNG LẶP NHỎ ---
    for ($i = 1; $i -le $N; $i++) {
        $arguments = @(
            "--decrypt",
            "--in", $inputFile,
            "--out", $outputFile,
            "--mode", $mode,
            "--keylen", $keylen,
            "--threads", $threads,
            "--encode", "hex",
            "--key-hex", $keyHex
        )

        if ($mode -eq "GCM" -or $mode -eq "CCM") {
            $arguments += "--nonce-hex", $ivOrNonceHex
        } elseif ($mode -ne "ECB") {
            $arguments += "--iv-hex", $ivOrNonceHex
        }

        # Chạy tool và lấy output
        $output = & .\mytool.exe $arguments 2>&1
        $outputText = $output -join "`n"

        # Tìm giá trị thời gian
        $match = $outputText | Select-String -Pattern "\[Time\]:\s*(\d+)\s*us"

        if ($match) {
            $ms = [double]$match.Matches.Groups[1].Value / 1000.0
            $setTimeMs += $ms
            $grandTotalTimeMs += $ms
            Add-Content -Path $logFile -Value $ms
        }

        # In tiến trình
        if ($i % 100 -eq 0) {
            $avg = $setTimeMs / $i
            Write-Host "Đã hoàn thành $i / $N lần | Trung bình (lần này): $([math]::Round($avg, 3)) ms/lần"
        }
    }

    $setAvgMs = $setTimeMs / $N
    Write-Host "✅ Hoàn tất Lần $j. Trung bình (lần này): $([math]::Round($setAvgMs, 3)) ms/lần"

    if ($j -lt $TotalSets) {
        Write-Host "...Nghỉ 5 giây trước khi chạy lần tiếp theo..."
        Start-Sleep -Seconds 5
    }

    Write-Host "----------------------------------------"
}

# --- KẾT THÚC ---
$grandAvgMs = $grandTotalTimeMs / $totalRuns

Write-Host "========================================"
Write-Host "✅ HOÀN TẤT TẤT CẢ $TotalSets LẦN CHẠY (DECRYPT)!"
Write-Host ("⏱️ Tổng số lần lặp: {0}" -f $totalRuns)
Write-Host ("⏱️ Trung bình thời gian 1k vòng:    {0:N3} ms" -f $grandTotalTimeMs)
Write-Host ("⏱️ TRUNG BÌNH CHUNG: {0:N3} ms/lần" -f $grandAvgMs)
Write-Host "========================================"
Write-Host "📁 Dữ liệu chi tiết được lưu trong: $logFile"
