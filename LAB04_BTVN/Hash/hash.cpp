#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

// OS Specific includes for CPU Pinning (Windows)
#ifdef _WIN32
#include <windows.h>
#else
#include <sched.h>
#include <pthread.h>
#endif

#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <sstream>
#include <vector>
#include <map>
#include <algorithm>
#include <memory>
#include <cstring>

// Crypto++
#include <cryptlib.h>
#include <sha.h>
#include <sha3.h>
#include <shake.h>
#include <md5.h>
#include <hex.h>
#include <filters.h>
#include <files.h>

using CryptoPP::byte;
#undef byte

// ==========================================================
// OPTIMIZATION HELPERS
// ==========================================================

// 1. Anti-optimization trick
inline void DoNotOptimize(const void* p) {
    asm volatile("" : : "g"(p) : "memory");
}

// 2. CPU Pinning & Priority (Giúp kết quả ổn định hơn)
void OptimizeThread() {
#ifdef _WIN32
    // Windows: Ghim vào Core 1, Set ưu tiên cao nhất
    HANDLE hThread = GetCurrentThread();
    SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
    SetThreadAffinityMask(hThread, 1 << 0); 
#else
    // Linux: Ghim vào CPU 0 (nếu chạy quyền root/phù hợp)
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#endif
}

// ==========================================================
// DATA STRUCTURES
// ==========================================================
struct KatEntry {
    std::string data;
    long long count;
    std::string note;
    std::map<std::string, std::string> expectedHashes;
};

struct BenchmarkResult {
    double totalSeconds;
    double avgTimePerRun;
    double throughputMBps;
    size_t totalBytes;
    int runs;
};

// ==========================================================
// FORWARD DECLARATIONS
// ==========================================================
std::string ByteToHex(const std::string& input);
std::string HexToByte(const std::string& input);
void ModifyOutputExtension(std::string& output);
size_t GetFileSize(const std::string& filename);
std::string EscapeJson(const std::string& input);
std::string GetTimestamp();
void SaveMetadata(const std::string& outputFile, const std::string& mode, 
                  long long inputSize, double runtimeSeconds);

// KAT Functions
std::vector<KatEntry> ParseKatFile(const std::string& filename);
void RunKatTests(const std::string& filename);

// Core Hash Functions
template <typename HashType>
void ComputeHashOnce(const std::string& data, bool isFile, std::string& outputFile, 
                     int shakeLen, const std::string& modeName);

// Benchmark Template (Core Logic)
template <typename HashType>
BenchmarkResult BenchmarkHash(int times, const std::string& data, bool isFile, int shakeLen);

template <typename HashType>
bool VerifyHashKat(const std::string& seedData, long long count, const std::string& expectedHex);

// Dispatchers
void ExecuteHash(const std::string& data, bool isFile, std::string& outputFile, 
                const std::string& mode, int shakeLen);
void ExecuteBenchmark(int times, const std::string& data, bool isFile, 
                     const std::string& mode, int shakeLen);

// ==========================================================
// MAIN
// ==========================================================
int main(int argc, char* argv[]) {
    // Tối ưu hóa I/O stream của C++
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    std::string inputFile, inputText, outputFilename = "output.bin";
    std::string mode = "SHA-256";
    std::string outlength = "256";
    
    bool runKat = false;
    std::string katFile = "kat.json";
    int repeatTimes = 1;
    bool benchmark = false;
    bool verbose = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--in" && i + 1 < argc) {
            inputFile = argv[++i];
        } else if (arg == "--text" && i + 1 < argc) {
            inputText = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            outputFilename = argv[++i];
        } else if (arg == "--mode" && i + 1 < argc) {
            mode = argv[++i];
        } else if (arg == "--outlen" && i + 1 < argc) {
            outlength = argv[++i];
        } else if (arg == "--kat") {
            runKat = true;
        } else if (arg == "--katFile" && i + 1 < argc) {
            katFile = argv[++i];
            runKat = true;
        } else if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--benchmark") {
            benchmark = true;
        } else if ((arg == "--t" || arg == "-t") && i + 1 < argc) {
            repeatTimes = std::stoi(argv[++i]);
            if (repeatTimes < 1) repeatTimes = 1;
        }
    }

    // KAT mode
    if (runKat) {
        RunKatTests(katFile);
        return 0;
    }

    // Setup parameters
    ModifyOutputExtension(outputFilename);
    int shakeLen = std::stoi(outlength) / 8;

    try {
        if (verbose) {
            std::cout << "Input: " << (inputFile.empty() ? inputText : inputFile) << std::endl;
            
            long long inputSize = inputFile.empty() ? inputText.size() : GetFileSize(inputFile);
            std::cout << "Input size: " << inputSize << " bytes" << std::endl;
            std::cout << "Digest Mode: " << mode << std::endl;
            
            if (benchmark) {
                std::cout << "Benchmark Runs: " << repeatTimes << std::endl;
                std::cout << "Optimizations: RAM Buffer, Direct Update, CPU Pinning, Warm-up" << std::endl;
            } else {
                std::cout << "Output File: " << outputFilename << std::endl;
            }
            
            if (mode == "SHAKE128" || mode == "SHAKE256") {
                std::cout << "Output Length: " << shakeLen << " bytes" << std::endl;
            }
        }

        if (!inputFile.empty()) {
            if (benchmark) {
                ExecuteBenchmark(repeatTimes, inputFile, true, mode, shakeLen);
            } else {
                ExecuteHash(inputFile, true, outputFilename, mode, shakeLen);
            }
        } else if (!inputText.empty()) {
            if (benchmark) {
                ExecuteBenchmark(repeatTimes, inputText, false, mode, shakeLen);
            } else {
                ExecuteHash(inputText, false, outputFilename, mode, shakeLen);
            }
        } else {
            std::cerr << "Error: No input provided.\nUsage:\n"
                      << "  Hash File:    --in <file> --mode <algo> [--out <file>] [--verbose]\n"
                      << "  Hash Text:    --text \"content\" --mode <algo>\n"
                      << "  Benchmark:    --in <file> --benchmark -t <times> --mode <algo>\n"
                      << "  Run KAT:      --kat [--katFile <file>]\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

// ==========================================================
// UTILITY FUNCTIONS
// ==========================================================
void ModifyOutputExtension(std::string& output) {
    size_t pos = output.rfind('.');
    if (pos != std::string::npos) {
        output = output.substr(0, pos) + ".bin";
    } else {
        output += ".bin";
    }
}

std::string ByteToHex(const std::string& input) {
    std::string output;
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(output)));
    return output;
}

std::string HexToByte(const std::string& input) {
    std::string output;
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(output)));
    return output;
}

size_t GetFileSize(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) return 0;
    return file.tellg();
}

std::string EscapeJson(const std::string& input) {
    std::string output;
    output.reserve(input.length());
    for (char c : input) {
        switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default: output += c; break;
        }
    }
    return output;
}

std::string GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    char buffer[100];
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now_c))) {
        return std::string(buffer);
    }
    return "Unknown";
}

void SaveMetadata(const std::string& outputFile, const std::string& mode,
                  long long inputSize, double runtimeSeconds) {
    std::string filename = outputFile + ".meta.json";
    std::string existingContent;
    
    std::ifstream readFile(filename);
    if (readFile) {
        existingContent.assign(std::istreambuf_iterator<char>(readFile),
                             std::istreambuf_iterator<char>());
    }

    std::ofstream jsonFile(filename);
    if (!jsonFile.is_open()) return;

    std::ostringstream newEntry;
    newEntry << "  {\n"
             << "    \"timestamp\": \"" << EscapeJson(GetTimestamp()) << "\",\n"
             << "    \"mode\": \"" << EscapeJson(mode) << "\",\n"
             << "    \"input_size_bytes\": " << inputSize << ",\n"
             << "    \"output_file\": \"" << EscapeJson(outputFile) << "\",\n"
             << "    \"runtime_seconds\": " << std::fixed << std::setprecision(6) 
             << runtimeSeconds << "\n"
             << "  }";

    std::string finalJson;
    if (existingContent.empty()) {
        finalJson = "[\n" + newEntry.str() + "\n]";
    } else {
        size_t lastBracket = existingContent.find_last_of(']');
        if (lastBracket != std::string::npos) {
            std::string before = existingContent.substr(0, lastBracket);
            while (!before.empty() && std::isspace(static_cast<unsigned char>(before.back()))) {
                before.pop_back();
            }
            if (before.find_last_of('}') != std::string::npos) {
                finalJson = before + ",\n" + newEntry.str() + "\n]";
            } else {
                finalJson = before + "\n" + newEntry.str() + "\n]";
            }
        } else {
            finalJson = "[\n" + newEntry.str() + "\n]";
        }
    }
    
    jsonFile << finalJson;
    std::cout << "Metadata saved to: " << filename << std::endl;
}

// ==========================================================
// KAT IMPLEMENTATION
// ==========================================================
std::string ExtractJsonValue(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t keyPos = json.find(searchKey);
    if (keyPos == std::string::npos) return "";

    size_t colonPos = json.find(":", keyPos);
    size_t valueStart = json.find_first_not_of(" \t\n\r", colonPos + 1);
    
    if (json[valueStart] == '"') {
        size_t endQuote = json.find("\"", valueStart + 1);
        return json.substr(valueStart + 1, endQuote - valueStart - 1);
    } else {
        size_t valueEnd = json.find_first_of(",}", valueStart);
        return json.substr(valueStart, valueEnd - valueStart);
    }
}

std::vector<KatEntry> ParseKatFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open KAT file " << filename << std::endl;
        return {};
    }
    
    std::string content{std::istreambuf_iterator<char>(file),
                       std::istreambuf_iterator<char>()};
    std::vector<KatEntry> entries;
    size_t objectStart = 0;
    
    while ((objectStart = content.find("{", objectStart)) != std::string::npos) {
        size_t messageKeyPos = content.find("\"message\"", objectStart);
        size_t objectEnd = content.find("}", objectStart);
        objectEnd = content.find("}", objectEnd + 1);
        
        if (messageKeyPos == std::string::npos || objectEnd == std::string::npos) {
            objectStart++;
            continue;
        }

        std::string block = content.substr(objectStart, objectEnd - objectStart + 1);
        KatEntry entry;
        
        size_t msgStart = block.find("{");
        size_t msgEnd = block.find("}");
        std::string msgBlock = block.substr(msgStart, msgEnd - msgStart + 1);
        
        entry.data = ExtractJsonValue(msgBlock, "data");
        entry.note = ExtractJsonValue(msgBlock, "note");
        std::string countStr = ExtractJsonValue(msgBlock, "count");
        entry.count = countStr.empty() ? 1 : std::stoll(countStr);

        size_t searchPos = msgEnd;
        while (true) {
            size_t keyStart = block.find("\"SHA", searchPos);
            if (keyStart == std::string::npos) break;
            
            size_t keyEnd = block.find("\"", keyStart + 1);
            std::string algoKey = block.substr(keyStart + 1, keyEnd - keyStart - 1);
            std::string hashVal = ExtractJsonValue(block.substr(keyStart), algoKey);
            entry.expectedHashes[algoKey] = hashVal;
            
            searchPos = keyEnd + 1;
        }
        
        entries.push_back(entry);
        objectStart = objectEnd + 1;
    }
    return entries;
}

template <typename HashType>
bool VerifyHashKat(const std::string& seedData, long long count, const std::string& expectedHex) {
    HashType hash;
    
    for (long long i = 0; i < count; i++) {
        hash.Update((const byte*)seedData.data(), seedData.size());
    }
    
    std::string digestRaw(hash.DigestSize(), '\0');
    hash.Final((byte*)&digestRaw[0]);
    
    std::string hexOutput = ByteToHex(digestRaw);
    std::transform(hexOutput.begin(), hexOutput.end(), hexOutput.begin(), ::tolower);
    
    std::string expectedLower = expectedHex;
    std::transform(expectedLower.begin(), expectedLower.end(), expectedLower.begin(), ::tolower);

    return hexOutput == expectedLower;
}

void RunKatTests(const std::string& filename) {
    std::cout << ">>> STARTING KAT from " << filename << " <<<\n";
    std::vector<KatEntry> entries = ParseKatFile(filename);
    
    if (entries.empty()) {
        std::cerr << "No valid entries found.\n";
        return;
    }

    std::string csvFilename = "hash_kat_results.csv";
    std::ofstream csv(csvFilename);
    if (csv.is_open()) {
        csv << "filename,count,algorithm,pass\n";
    }
    
    std::string filenameOnly = filename;
    size_t lastSlash = filename.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        filenameOnly = filename.substr(lastSlash + 1);
    }

    int totalTests = 0, passTests = 0;

    for (const auto& entry : entries) {
        std::cout << "--------------------------------------------------\n";
        std::cout << "Test: " << entry.note << "\n";
        std::cout << "Length: " << entry.data.length() << " | Repeat: " << entry.count << "\n";
        
        for (const auto& [algo, expected] : entry.expectedHashes) {
            bool result = false;
            
            if (algo == "SHA-1") result = VerifyHashKat<CryptoPP::SHA1>(entry.data, entry.count, expected);
            else if (algo == "SHA-224") result = VerifyHashKat<CryptoPP::SHA224>(entry.data, entry.count, expected);
            else if (algo == "SHA-256") result = VerifyHashKat<CryptoPP::SHA256>(entry.data, entry.count, expected);
            else if (algo == "SHA-384") result = VerifyHashKat<CryptoPP::SHA384>(entry.data, entry.count, expected);
            else if (algo == "SHA-512") result = VerifyHashKat<CryptoPP::SHA512>(entry.data, entry.count, expected);
            else if (algo == "SHA-3-224") result = VerifyHashKat<CryptoPP::SHA3_224>(entry.data, entry.count, expected);
            else if (algo == "SHA-3-256") result = VerifyHashKat<CryptoPP::SHA3_256>(entry.data, entry.count, expected);
            else if (algo == "SHA-3-384") result = VerifyHashKat<CryptoPP::SHA3_384>(entry.data, entry.count, expected);
            else if (algo == "SHA-3-512") result = VerifyHashKat<CryptoPP::SHA3_512>(entry.data, entry.count, expected);
            else {
                std::cout << "[SKIP] " << algo << "\n";
                continue;
            }

            totalTests++;
            if (result) {
                passTests++;
                std::cout << "[PASS] " << algo << "\n";
            } else {
                std::cout << "[FAIL] " << algo << " (Expected: " << expected << ")\n";
            }

            if (csv.is_open()) {
                csv << filenameOnly << "," << entry.count << "," 
                    << algo << "," << (result ? "1" : "0") << "\n";
            }
        }
    }
    
    if (csv.is_open()) {
        csv.close();
        std::cout << "Results saved to " << csvFilename << "\n";
    }

    std::cout << "==================================================\n";
    std::cout << "KAT SUMMARY: " << passTests << "/" << totalTests << " passed\n";
}

// ==========================================================
// HASH COMPUTATION (NORMAL MODE)
// ==========================================================
template <typename HashType>
void ComputeHashOnce(const std::string& data, bool isFile, std::string& outputFile,
                     int shakeLen, const std::string& modeName) {
    std::string digestRaw;
    HashType hash;
    long long inputSize = 0;
    
    // Sử dụng HashFilter cho mode thường (để tiện lợi, không phải benchmark)
    // Nếu muốn tối ưu cả ở đây, có thể chuyển sang Update() loop như Benchmark
    auto* hashFilter = new CryptoPP::HashFilter(hash,
        new CryptoPP::StringSink(digestRaw), false, shakeLen);

    auto start = std::chrono::steady_clock::now();

    try {
        if (isFile) {
            inputSize = GetFileSize(data);
            CryptoPP::FileSource fs(data.c_str(), true, hashFilter);
        } else {
            inputSize = data.size();
            CryptoPP::StringSource ss(data, true, hashFilter);
        }
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Hash failed: " + std::string(e.what()));
    }

    auto end = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();

    std::string hexOutput = ByteToHex(digestRaw);
    std::cout << "Digest (Hex): " << hexOutput << std::endl;

    CryptoPP::StringSource(digestRaw, true, new CryptoPP::FileSink(outputFile.c_str()));

    std::cout << "Time: " << std::fixed << std::setprecision(6) << elapsed << " s";
    if (isFile && inputSize > 0) {
        double mbs = (inputSize / (1024.0 * 1024.0)) / elapsed;
        std::cout << " | Speed: " << std::fixed << std::setprecision(2) << mbs << " MB/s";
    }
    std::cout << std::endl;

    SaveMetadata(outputFile, modeName, inputSize, elapsed);
}

// ==========================================================
// OPTIMIZED BENCHMARK (HIGH PERFORMANCE)
// ==========================================================
template <typename HashType>
BenchmarkResult BenchmarkHash(int times, const std::string& data, bool isFile, int shakeLen) {
    if (times <= 0) times = 1;

    // 1. OS Optimization: Pin thread to CPU 0, Max Priority
    OptimizeThread();

    // 2. Load data into RAM once
    std::string buffer;
    if (isFile) {
        std::ifstream in(data, std::ios::binary | std::ios::ate);
        if (!in) throw std::runtime_error("Cannot open file");
        auto fsize = in.tellg();
        buffer.resize(fsize);
        in.seekg(0);
        in.read(&buffer[0], fsize);
    } else {
        buffer = data;
    }

    const size_t size = buffer.size();
    if (size == 0) throw std::runtime_error("Empty data");

    // 3. Prepare digest buffer (outside loop)
    unsigned int digestSize = (shakeLen > 0) ? shakeLen : HashType::DIGESTSIZE;
    std::vector<byte> digest(digestSize);
    HashType hash;

    // 4. WARM-UP Phase (Chạy nóng CPU cache)
    for(int i=0; i<3; ++i) {
        hash.Update((const byte*)buffer.data(), size);
        if (shakeLen > 0) hash.TruncatedFinal(digest.data(), digestSize);
        else hash.Final(digest.data());
        hash.Restart();
    }
    
    std::cout << "--- Benchmarking " << times << " runs (Optimization Enabled) ---\n";

    // 5. CRITICAL LOOP (Sử dụng Steady Clock)
    auto start = std::chrono::steady_clock::now();

    for (int i = 0; i < times; i++) {
        // Direct update (Không qua Filters)
        hash.Update((const byte*)buffer.data(), size);
        
        // Finalize
        if (shakeLen > 0) hash.TruncatedFinal(digest.data(), digestSize);
        else hash.Final(digest.data());

        // Anti-optimization (Ngăn compiler xóa code)
        DoNotOptimize(digest.data());
        
        // Reset state
        hash.Restart();
    }

    auto end = std::chrono::steady_clock::now();

    // 6. Calculate results
    BenchmarkResult result;
    result.runs = times;
    result.totalBytes = size * times;
    result.totalSeconds = std::chrono::duration<double>(end - start).count();
    result.avgTimePerRun = result.totalSeconds / times;
    
    double totalMB = result.totalBytes / (1024.0 * 1024.0);
    result.throughputMBps = totalMB / result.totalSeconds;

    return result;
}

// ==========================================================
// DISPATCHERS
// ==========================================================
void ExecuteHash(const std::string& data, bool isFile, std::string& outputFile,
                 const std::string& mode, int shakeLen) {
    if (mode == "SHA-224") ComputeHashOnce<CryptoPP::SHA224>(data, isFile, outputFile, -1, mode);
    else if (mode == "SHA-256") ComputeHashOnce<CryptoPP::SHA256>(data, isFile, outputFile, -1, mode);
    else if (mode == "SHA-384") ComputeHashOnce<CryptoPP::SHA384>(data, isFile, outputFile, -1, mode);
    else if (mode == "SHA-512") ComputeHashOnce<CryptoPP::SHA512>(data, isFile, outputFile, -1, mode);
    else if (mode == "SHA3-224") ComputeHashOnce<CryptoPP::SHA3_224>(data, isFile, outputFile, -1, mode);
    else if (mode == "SHA3-256") ComputeHashOnce<CryptoPP::SHA3_256>(data, isFile, outputFile, -1, mode);
    else if (mode == "SHA3-384") ComputeHashOnce<CryptoPP::SHA3_384>(data, isFile, outputFile, -1, mode);
    else if (mode == "SHA3-512") ComputeHashOnce<CryptoPP::SHA3_512>(data, isFile, outputFile, -1, mode);
    else if (mode == "SHAKE128") ComputeHashOnce<CryptoPP::SHAKE128>(data, isFile, outputFile, shakeLen, mode);
    else if (mode == "SHAKE256") ComputeHashOnce<CryptoPP::SHAKE256>(data, isFile, outputFile, shakeLen, mode);
    else if (mode == "MD5") ComputeHashOnce<CryptoPP::Weak::MD5>(data, isFile, outputFile, -1, mode);
    else throw std::runtime_error("Unknown mode: " + mode);
}

void ExecuteBenchmark(int times, const std::string& data, bool isFile,
                      const std::string& mode, int shakeLen) {
    BenchmarkResult result;
    
    try {
        if (mode == "SHA-224") result = BenchmarkHash<CryptoPP::SHA224>(times, data, isFile, -1);
        else if (mode == "SHA-256") result = BenchmarkHash<CryptoPP::SHA256>(times, data, isFile, -1);
        else if (mode == "SHA-384") result = BenchmarkHash<CryptoPP::SHA384>(times, data, isFile, -1);
        else if (mode == "SHA-512") result = BenchmarkHash<CryptoPP::SHA512>(times, data, isFile, -1);
        else if (mode == "SHA3-224") result = BenchmarkHash<CryptoPP::SHA3_224>(times, data, isFile, -1);
        else if (mode == "SHA3-256") result = BenchmarkHash<CryptoPP::SHA3_256>(times, data, isFile, -1);
        else if (mode == "SHA3-384") result = BenchmarkHash<CryptoPP::SHA3_384>(times, data, isFile, -1);
        else if (mode == "SHA3-512") result = BenchmarkHash<CryptoPP::SHA3_512>(times, data, isFile, -1);
        else if (mode == "SHAKE128") result = BenchmarkHash<CryptoPP::SHAKE128>(times, data, isFile, shakeLen);
        else if (mode == "SHAKE256") result = BenchmarkHash<CryptoPP::SHAKE256>(times, data, isFile, shakeLen);
        else if (mode == "MD5") result = BenchmarkHash<CryptoPP::Weak::MD5>(times, data, isFile, -1);
        else throw std::runtime_error("Unknown mode: " + mode);
        
        std::cout << std::fixed << std::setprecision(6);
        std::cout << "Total Time: " << result.totalSeconds << " s\n";
        std::cout << "Avg Time:   " << result.avgTimePerRun << " s/run\n";
        std::cout << std::setprecision(2);
        std::cout << "Throughput: " << result.throughputMBps << " MB/s\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Benchmark failed: " << e.what() << std::endl;
    }
}