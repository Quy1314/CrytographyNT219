# ====== CẤU HÌNH ======
$inputDir = "6TESTFile"
$outputDirEnc = "Encrypted_Files"
$outputDirDec = "Decrypted_Files"
$logFile = "time.txt"

$files = @("1KB.bin","4KB.bin","16KB.bin","256KB.bin","1MB.bin","4MB.bin","8MB.bin")
$modes = @("ECB","CBC","CFB","OFB","CTR","GCM","CCM","XTS")

# ==== KEY & IV/NONCE HARDCORE ====
$keylen_default = 128
$keyHex_128 = "00112233445566778899AABBCCDDEEFF"
$keylen_xts = 256
$keyHex_256 = "00112233445566778899AABBCCDDEEFF112233445566778899AABBCCDDEEFF00"

# IV / NONCE cố định để tất cả decrypt được
$ivHex = "AABBCCDDEEFF00112233445566778899"
$nonceHex = "FCDA01DB500F48DEE370B9A1"

$threads = 16
# ======================

# Tạo thư mục output
New-Item -ItemType Directory -Path $outputDirEnc -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path $outputDirDec -ErrorAction SilentlyContinue | Out-Null

# Xóa log cũ
Remove-Item -Path $logFile -ErrorAction SilentlyContinue
Add-Content -Path $logFile -Value "File,Mode,Operation,Time(us)"

$totalCommands = $files.Count * $modes.Count * 2
Write-Host "Bắt đầu benchmark 8 mode cho $($files.Count) file (Tổng cộng $totalCommands lệnh)" -ForegroundColor Yellow

# =====================
# 1️⃣ ENCRYPT TOÀN BỘ
# =====================
foreach ($file in $files) {
    $inputFile = "$inputDir\$file"
    foreach ($mode in $modes) {
        Write-Host "--- ENCRYPT: $file | Mode: $mode ---" -ForegroundColor Cyan

        $currentKey = $keyHex_128
        $currentKeyLen = $keylen_default
        if ($mode -eq "XTS") {
            $currentKey = $keyHex_256
            $currentKeyLen = $keylen_xts
            Write-Host "Sử dụng key 256-bit riêng cho XTS..."
        }

        $outputFileEnc = "$outputDirEnc/$($file -replace '\.bin','')_$($mode)_ENCRYPTED.bin"

        $argumentsEnc = @(
            "--encrypt","--in",$inputFile,"--out",$outputFileEnc,
            "--mode",$mode,"--keylen",$currentKeyLen,"--threads",$threads,
            "--encode","hex","--key-hex",$currentKey
        )

        # IV/NONCE hardcore
        if ($mode -eq "ECB") {
            $argumentsEnc += "--allow-ecb"
        } elseif ($mode -eq "GCM" -or $mode -eq "CCM") {
            $argumentsEnc += "--aead","--nonce-hex",$nonceHex
        } else {
            $argumentsEnc += "--iv-hex",$ivHex
        }

        $outputEnc = & .\mytool.exe $argumentsEnc *>&1
        Write-Host $outputEnc

        $matchEnc = $outputEnc | Select-String -Pattern "\[Time\]:(\d+)\s*us"
        if ($matchEnc) {
            $timeUs = $matchEnc.Matches.Groups[1].Value
            Add-Content -Path $logFile -Value "$file,$mode,ENCRYPT,$timeUs"
        }
    }
}

# =====================
# 2️⃣ DECRYPT TOÀN BỘ
# =====================
foreach ($file in $files) {
    foreach ($mode in $modes) {
        Write-Host "--- DECRYPT: $file | Mode: $mode ---" -ForegroundColor Green

        $currentKey = $keyHex_128
        $currentKeyLen = $keylen_default
        if ($mode -eq "XTS") {
            $currentKey = $keyHex_256
            $currentKeyLen = $keylen_xts
        }

        $inputFileDec = "$outputDirEnc/$($file -replace '\.bin','')_$($mode)_ENCRYPTED.bin"
        $outputFileDec = "$outputDirDec/$($file -replace '\.bin','')_$($mode)_DECRYPTED.bin"

        $argumentsDec = @(
            "--decrypt","--in",$inputFileDec,"--out",$outputFileDec,
            "--mode",$mode,"--keylen",$currentKeyLen,"--threads",$threads,
            "--encode","hex","--key-hex",$currentKey
        )

        if ($mode -eq "ECB") {
            $argumentsDec += "--allow-ecb"
        } elseif ($mode -eq "GCM" -or $mode -eq "CCM") {
            $argumentsDec += "--aead","--nonce-hex",$nonceHex
        } else {
            $argumentsDec += "--iv-hex",$ivHex
        }

        if (Test-Path $inputFileDec) {
            $outputDec = & .\mytool.exe $argumentsDec *>&1
            Write-Host $outputDec
            $matchDec = $outputDec | Select-String -Pattern "\[Time\]:(\d+)\s*us"
            if ($matchDec) {
                $timeUs = $matchDec.Matches.Groups[1].Value
                Add-Content -Path $logFile -Value "$file,$mode,DECRYPT,$timeUs"
            }
        } else {
            Write-Host "⚠️ Bỏ qua decrypt vì file $inputFileDec không tồn tại!" -ForegroundColor Red
        }
    }
}

Write-Host "--- ✅ HOÀN TẤT TOÀN BỘ ENCRYPT + DECRYPT ---" -ForegroundColor Yellow
Write-Host "📁 Log kết quả: $logFile" -ForegroundColor Yellow
