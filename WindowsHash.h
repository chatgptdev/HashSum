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

#ifndef WINDOWS_HASH_H
#define WINDOWS_HASH_H

#include <Windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>

class WindowsHash {
public:
    WindowsHash();
    ~WindowsHash();

    bool Init(const std::string& algorithm);
    bool Update(const unsigned char* data, size_t dataSize);
    bool Final(std::vector<unsigned char>& digest);

    static std::vector<std::string> GetSupportedAlgorithms();
    static size_t GetDigestSize(const std::string& algorithm);

private:
    bool initialized;
    BCRYPT_ALG_HANDLE hAlgorithm;
    BCRYPT_HASH_HANDLE hHash;
};

#endif // WINDOWS_HASH_H
