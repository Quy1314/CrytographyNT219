# ====== CẤU HÌNH ======
$N = 1000                                  # Số lần chạy (mỗi lần lớn)
$TotalSets = 10                            # <--- MỚI: Tổng số "lần lớn" (1 lần đầu + 9 lần sau)
$logFile = "CBC_4KB_log.txt"               # File ghi log
$inputFile = "6TESTFile\4KB.bin"           # File dữ liệu đầu vào
$outputFile = "benchmark_output\4KB_CBC_out.bin"                # File xuất
$mode = "CBC"                              # Chế độ AES
$keylen = 128                              # Độ dài khóa
$threads = 16                               # Số luồng

# Key 128-bit = 16 bytes = 32 ký tự hex
$keyHex = "00112233445566778899AABBCCDDEEFF"
# IV/Nonce (16 bytes = 32 ký tự hex)
$ivOrNonceHex = "AABBCCDDEEFF00112233445566778899"
# ======================

# Xóa log cũ nếu tồn tại
if (Test-Path $logFile) { Remove-Item $logFile }

# ✅ Biến tổng cho TẤT CẢ các lần chạy
$grandTotalTimeMs = 0
$totalRuns = $N * $TotalSets

Write-Host "Bắt đầu benchmark $TotalSets lần (mỗi lần $N lặp, tổng cộng $totalRuns lặp)..."
Write-Host "Key: $keyHex"
Write-Host "IV/Nonce: $ivOrNonceHex"


# --- VÒNG LẶP LỚN (Chạy $TotalSets = 10 lần) ---
for ($j = 1; $j -le $TotalSets; $j++) {
    
    Write-Host "----------------------------------------"
    Write-Host "Bắt đầu Lần chạy Lớn $j / $TotalSets..."
    
    $setTimeMs = 0 # Tổng thời gian cho riêng "lần lớn" này

    # --- VÒNG LẶP NHỎ (Chạy $N = 1000 lần - Code gốc của bạn) ---
    for ($i = 1; $i -le $N; $i++) {
    
        # Xây dựng danh sách đối số
        $arguments = @(
            "--encrypt",
            "--in", $inputFile,
            "--out", $outputFile,
            "--mode", $mode,
            "--keylen", $keylen,
            "--threads", $threads,
            "--encode", "hex",
            "--key-hex", $keyHex
        )
    
        # Tự động thêm IV hoặc Nonce
        if ($mode -eq "GCM" -or $mode -eq "CCM") {
            $arguments += "--nonce-hex", $ivOrNonceHex
        } elseif ($mode -ne "ECB") {
            $arguments += "--iv-hex", $ivOrNonceHex
        }
    
        # Chạy lệnh và LẤY KẾT QUẢ OUTPUT
        $output = & .\mytool.exe $arguments 2>&1
    
        # Tìm giá trị thời gian trong output
        $match = $output | Select-String -Pattern "\[Time\]:(\d+)\s*us"
    
        if ($match) {
            # CHUYỂN VỀ MS
            $ms = [double]$match.Matches.Groups[1].Value / 1000.0
            
            # CỘNG LẠI (Cộng dồn vào biến tổng)
            $setTimeMs += $ms       # Cộng vào tổng của lần này
            $grandTotalTimeMs += $ms # Cộng vào tổng của TẤT CẢ
            
            Add-Content -Path $logFile -Value $ms 
        }
    
        # In tiến trình mỗi 100 lần
        if ($i % 100 -eq 0) {
            $avg = $setTimeMs / $i # <--- Tính trung bình của riêng lần này
            Write-Host "Đã hoàn thành $i / $N lần | Trung bình (lần này): $([math]::Round($avg, 3)) ms/lần"
        }
    }
    # --- KẾT THÚC VÒNG LẶP NHỎ ---

    $setAvgMs = $setTimeMs / $N
    Write-Host "✅ Hoàn tất Lần $j. Trung bình (lần này): $([math]::Round($setAvgMs, 3)) ms/lần"

    # --- LOGIC NGHỈ 5 GIÂY ---
    if ($j -lt $TotalSets) { # Chỉ nghỉ nếu đây không phải là lần cuối cùng
        Write-Host "...Nghỉ 5 giây trước khi chạy lần tiếp theo..."
        Start-Sleep -Seconds 5
    }
}
# --- KẾT THÚC VÒNG LẶP LỚN ---


# Tính toán kết quả cuối cùng
$grandAvgMs = $grandTotalTimeMs / $totalRuns

Write-Host "========================================"
Write-Host "✅ HOÀN TẤT TẤT CẢ $TotalSets LẦN CHẠY!"
Write-Host ("⏱️ Tổng số lần lặp: {0}" -f $totalRuns)
Write-Host ("⏱️ Tổng thời gian:    {0:N3} ms" -f $grandTotalTimeMs)
Write-Host ("⏱️ TRUNG BÌNH CHUNG: {0:N3} ms/lần" -f $grandAvgMs)
Write-Host "========================================"
Write-Host "📁 Dữ liệu chi tiết được lưu trong: $logFile"