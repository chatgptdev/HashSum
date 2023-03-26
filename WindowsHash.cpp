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

#include "WindowsHash.h"
#include <algorithm>

WindowsHash::WindowsHash() : hAlgorithm(nullptr), hHash(nullptr), initialized(false) {}

WindowsHash::~WindowsHash() {
    if (initialized) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
}

bool WindowsHash::Init(const std::string& algorithm) {
    std::string lowerAlgorithm = algorithm;
    std::transform(lowerAlgorithm.begin(), lowerAlgorithm.end(), lowerAlgorithm.begin(), ::tolower);
    LPCWSTR algId;
    if (lowerAlgorithm == "md5") {
        algId = BCRYPT_MD5_ALGORITHM;
    } else if (lowerAlgorithm == "sha1" ) {
        algId = BCRYPT_SHA1_ALGORITHM;
    } else if (lowerAlgorithm == "sha256") {
        algId = BCRYPT_SHA256_ALGORITHM;
    } else if (lowerAlgorithm == "sha384") {
        algId = BCRYPT_SHA384_ALGORITHM;
    } else if (lowerAlgorithm == "sha512") {
        algId = BCRYPT_SHA512_ALGORITHM;
    } else {
        return false;
    }

    NTSTATUS status;

    // Open the algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, algId, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }

    // Create the hash object
    status = BCryptCreateHash(hAlgorithm, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return false;
    }

    initialized = true;
    return true;
}

bool WindowsHash::Update(const unsigned char* data, size_t dataSize) {
    if (!initialized) {
        return false;
    }

    NTSTATUS status = BCryptHashData(hHash, const_cast<PUCHAR>(data), dataSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }

    return true;
}

bool WindowsHash::Final(std::vector<unsigned char>& digest) {
    if (!initialized) {
        return false;
    }

    // Get the hash length
    DWORD hashLength;
    DWORD cbData;
    NTSTATUS status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PBYTE)&hashLength, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }

    // Resize the hash vector and finish the hash
    digest.resize(hashLength);
    status = BCryptFinishHash(hHash, digest.data(), hashLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        digest.clear();
        return false;
    }

    return true;
}



std::vector<std::string> WindowsHash::GetSupportedAlgorithms() {
    std::vector<std::string> supportedAlgorithms;

    supportedAlgorithms.push_back("md5");
    supportedAlgorithms.push_back("sha1");
    supportedAlgorithms.push_back("sha256");
    supportedAlgorithms.push_back("sha384");
    supportedAlgorithms.push_back("sha512");

    return supportedAlgorithms;
}

