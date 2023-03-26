/*
 * HashSum
 * 
 * Copyright (c) 2023 chatgptdev
 * 
 * This software was written mostly by ChatGPT 4.0 using instructions by
 * @chatgptdev. It is provided under the Apache License, Version 2.0 
 * (the "License"); you may not use this software except in compliance with
 * the License. You may obtain a copy of the License at:
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <filesystem>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <map>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <future>
#include <mutex>
#include <array>
#ifdef _WIN32
#include "WindowsHash.h"
#else
#include <openssl/evp.h>
#endif

namespace fs = std::filesystem;

std::mutex outputMutex;

class ThreadPool {
public:
    ThreadPool() : ThreadPool(std::thread::hardware_concurrency()) {}

    explicit ThreadPool(size_t numThreads) {
        for (size_t i = 0; i < numThreads; ++i) {
            threads.emplace_back([this] {
                while (true) {
                    std::function<void()> task;

                    {
                        std::unique_lock<std::mutex> lock(this->queueMutex);

                        this->condition.wait(lock, [this] {
                            return this->stop || !this->tasks.empty();
                        });

                        if (this->stop && this->tasks.empty()) {
                            return;
                        }

                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }

                    task();
                }
            });
        }
    }

    ~ThreadPool() {
        wait();
    }

    template<typename F, typename... Args>
    auto enqueue(F&& f, Args&&... args)
        -> std::future<typename std::result_of<F(Args...)>::type> {
        using return_type = typename std::result_of<F(Args...)>::type;

        auto task = std::make_shared<std::packaged_task<return_type()> >(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );

        std::future<return_type> result = task->get_future();

        {
            std::unique_lock<std::mutex> lock(queueMutex);

            if (stop) {
                throw std::runtime_error("Enqueue on stopped ThreadPool");
            }

            tasks.emplace([task]() {
                (*task)();
            });
        }

        condition.notify_one();
        return result;
    }
    
    void wait() {
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread& worker : threads) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

private:
    std::vector<std::thread> threads;
    std::queue<std::function<void()>> tasks;
    std::mutex queueMutex;
    std::condition_variable condition;
    std::atomic_bool stop{false};
};

std::string computeFileHash(const std::string& filePath, const std::string& hashAlgorithm) {
#ifdef _WIN32
    WindowsHash hasher;
    if (!hasher.Init(hashAlgorithm)) {
        throw std::runtime_error("Error: Unsupported hash algorithm.");
    }

    std::array<unsigned char, 4096> buffer;
    std::vector<unsigned char> digest;

    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Error: Unable to open the input file.");
    }

    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            if (!hasher.Update(buffer.data(), static_cast<std::size_t>(bytesRead))) {
                throw std::runtime_error("Error: Unable to update the hash.");
            }
        }
    }

    if (!hasher.Final(digest)) {
        throw std::runtime_error("Error: Unable to finalize the hash.");
    }

    std::stringstream ss;
    for (unsigned char byte : digest) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return ss.str();
#else
    const EVP_MD* md = EVP_get_digestbyname(hashAlgorithm.c_str());
    if (md == nullptr) {
        throw std::runtime_error("Error: Unsupported hash algorithm.");
    }

    std::array<unsigned char, 4096> buffer;
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest;
    unsigned int digestLength;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("Error: Unable to create a new message digest context.");
    }

    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error: Unable to initialize the message digest context.");
    }

    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error: Unable to open the input file.");
    }

    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            if (EVP_DigestUpdate(mdctx, buffer.data(), static_cast<std::size_t>(bytesRead)) != 1) {
                EVP_MD_CTX_free(mdctx);
                throw std::runtime_error("Error: Unable to update the message digest context.");
            }
        }
    }

    if (EVP_DigestFinal_ex(mdctx, digest.data(), &digestLength) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Error: Unable to finalize the message digest context.");
    }

    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < digestLength; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }

    return ss.str();
#endif
}

void processFile(const std::string& path, const fs::path& filePath, const std::string& hashAlgorithm, const std::string& outPath) {
        auto hash = computeFileHash(filePath.string(), hashAlgorithm);
        fs::path inputPathFs(path);
        fs::path relativePath;

        if (inputPathFs.parent_path() == filePath.parent_path()) {
            relativePath = filePath.filename();
        } else {
            relativePath = filePath.lexically_relative(inputPathFs);
        }

        std::string result = hash + "  " + relativePath.string() + "\n";

        // Lock the output mutex before writing to the output file
        std::unique_lock<std::mutex> lock(outputMutex);

        if (!outPath.empty()) {
            std::ofstream outFile(outPath, std::ios::app);
            if (!outFile.is_open()) {
                throw std::runtime_error("Error: Unable to open the output file.");
            }
            outFile << result;
            outFile.close();
        } else {
            std::cout << result;
        }

        // Unlock the output mutex
        lock.unlock();
    }

void computeDirectoryHash(const std::string& path, const std::string& hashAlgorithm, const std::string& outputPath, ThreadPool& threadPool) {

    fs::path inputPathFs(path);
    if (fs::is_directory(inputPathFs)) {
        for (const auto& entry : fs::recursive_directory_iterator(path)) {
            if (entry.is_regular_file()) {
                threadPool.enqueue(processFile,path, entry.path(), hashAlgorithm, outputPath);
            }
        }
    } else if (fs::is_regular_file(inputPathFs)) {
        threadPool.enqueue(processFile,path, inputPathFs, hashAlgorithm, outputPath); 
    } else {
        throw std::runtime_error("Error: The input path is neither a file nor a directory.");
    }
}


std::map<std::string, std::string> parseCommandLineArguments(int argc, char* argv[]) {
    std::map<std::string, std::string> arguments;

    if (argc > 1) {
        arguments["inputPath"] = argv[1];
    }

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg[0] == '-') {
            std::string key = arg.substr(1);
            if (i + 1 < argc) {
                std::string value = argv[i + 1];
                if (value[0] != '-') {
                    arguments[key] = value;
                    ++i;
                } else {
                    arguments[key] = "";
                }
            } else {
                arguments[key] = "";
            }
        }
    }

    return arguments;
}

#ifndef _WIN32
void add_supported_hash_algorithm(const EVP_MD* md, const char* name, const char* name2, void* arg) {
    std::vector<std::string>* algorithms = static_cast<std::vector<std::string>*>(arg);
    // Only add pure hash algorithms (name2 is NULL or name and name2 are equal)
    if(md && name && (!name2 || (0 == strcmp(name, name2)))) {
        algorithms->push_back(name);
    }
}
#endif

int main(int argc, char* argv[]) {
  try {
      std::map<std::string, std::string> arguments = parseCommandLineArguments(argc, argv);

      if (arguments.count("help") || arguments.count("inputPath") == 0) {
#ifdef _WIN32
          auto supported_algorithms = WindowsHash::GetSupportedHashAlgorithms();
#else
          std::vector<std::string> supported_algorithms;
          EVP_MD_do_all_sorted(add_supported_hash_algorithm, &supported_algorithms);
#endif
          std::cerr << "Usage: " << argv[0] << " INPUT_PATH [-o OUTPUT_PATH] [-a HASH_ALGORITHM] [-help]\n";
          std::cerr << "If OUTPUT_PATH is not specified, the output will be printed to the terminal\n";
          std::cerr << "HASH_ALGORITHM defaults to SHA256 if not specified.\n";
          std::cerr << "Supported hash algorithms: ";
          for (const auto& algorithm : supported_algorithms) {
              std::cerr << algorithm << " ";
          }
          std::cerr << std::endl;
          return 1;
      }

      std::string inputPath = arguments["inputPath"];
      std::string outputPath = arguments.count("o") ? arguments["o"] : "";
      std::string hashAlgorithm = arguments.count("a") ? arguments["a"] : "SHA256";
      
#ifdef _WIN32
      // Check if the hash algorithm is supported by WindowsHash
      WindowsHash hasher;
      if (!hasher.Init(hashAlgorithm)) {
          auto supported_algorithms = WindowsHash::GetSupportedHashAlgorithms();

          std::cerr << "Error: Unsupported hash algorithm: " << hashAlgorithm << std::endl;
          std::cerr << "Supported hash algorithms: ";
          for (const auto& algorithm : supported_algorithms) {
              std::cerr << algorithm << " ";
          }
          std::cerr << std::endl;
          return 1;
      }
#else
      // Check if the hash algorithm is supported by OpenSSL
      const EVP_MD* digest = EVP_get_digestbyname(hashAlgorithm.c_str());
      if (!digest) {
          std::vector<std::string> supported_algorithms;
          EVP_MD_do_all_sorted(add_supported_hash_algorithm, &supported_algorithms);

          std::cerr << "Error: Unsupported hash algorithm: " << hashAlgorithm << std::endl;
          std::cerr << "Supported hash algorithms: ";
          for (const auto& algorithm : supported_algorithms) {
              std::cerr << algorithm << " ";
          }
          std::cerr << std::endl;
          return 1;
      }
#endif

      unsigned int numThreads = std::thread::hardware_concurrency();
      ThreadPool threadPool(numThreads);

 
      computeDirectoryHash(inputPath, hashAlgorithm, outputPath, threadPool);
    
      // Wait for all tasks to finish
      threadPool.wait();
        

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
