# benchmark.ps1
# Chạy benchmark cho tất cả SHA modes trên 3 file và ghi kết quả vào result.txt

$hashExe = ".\hash.exe"
$times = 1000
$outputResult = "result.txt"

# Danh sách file test
$files = @(
    ".\1MB.bin",
    ".\10MB.bin",
    ".\100MB.bin"
)

# Danh sách hash mode
$modes = @(
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SHAKE128",
    "SHAKE256"
)

# Xóa file kết quả cũ
if (Test-Path $outputResult) {
    Remove-Item $outputResult
}

Add-Content $outputResult "==== Hash Benchmark Results ===="
Add-Content $outputResult "Times: $times"
Add-Content $outputResult "Start: $(Get-Date)"
Add-Content $outputResult ""

foreach ($file in $files) {
    $size = (Get-Item $file).Length
    Add-Content $outputResult "----- File: $file ($size bytes) -----"

    foreach ($mode in $modes) {
        $cmd = "$hashExe --mode $mode --benchmark -t $times --in `"$file`""
        Add-Content $outputResult "[+] Running: $cmd"
        
        try {
            $result = & $hashExe --mode $mode --benchmark -t $times --in $file 2>&1
            Add-Content $outputResult $result
        }
        catch {
            Add-Content $outputResult "[ERROR] $mode on $file"
        }

        Add-Content $outputResult ""
    }

    Add-Content $outputResult ""
}

Add-Content $outputResult "==== DONE ===="
Add-Content $outputResult "End: $(Get-Date)"
