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
 
#include "MacOSHash.h"
#include <algorithm>

macOSHash::macOSHash() : isInitialized(false) {}

macOSHash::~macOSHash() {}

bool macOSHash::Init(const std::string& algorithm) {
    std::string lowerAlgorithm = algorithm;
    std::transform(lowerAlgorithm.begin(), lowerAlgorithm.end(), lowerAlgorithm.begin(), ::tolower);
  
    isInitialized = false;

    if (lowerAlgorithm == "md5") {
        currentAlgorithm = HashAlgorithm::MD5;
        CC_MD5_Init(&md5_ctx);
    } else if (lowerAlgorithm == "sha1") {
        currentAlgorithm = HashAlgorithm::SHA1;
        CC_SHA1_Init(&sha1_ctx);
    } else if (lowerAlgorithm == "sha256") {
        currentAlgorithm = HashAlgorithm::SHA256;
        CC_SHA256_Init(&sha256_ctx);
    } else if (lowerAlgorithm == "sha384") {
        currentAlgorithm = HashAlgorithm::SHA384;
        CC_SHA384_Init(&sha384_ctx);
    } else if (lowerAlgorithm == "sha512") {
        currentAlgorithm = HashAlgorithm::SHA512;
        CC_SHA512_Init(&sha512_ctx);
    } else {
        return false;
    }

    isInitialized = true;
    return true;
}

bool macOSHash::Update(const unsigned char* data, size_t dataSize) {
    if (!isInitialized) {
        return false;
    }

    switch (currentAlgorithm) {
        case HashAlgorithm::MD5:
            CC_MD5_Update(&md5_ctx, data, dataSize);
            break;
        case HashAlgorithm::SHA1:
            CC_SHA1_Update(&sha1_ctx, data, dataSize);
            break;
        case HashAlgorithm::SHA256:
            CC_SHA256_Update(&sha256_ctx, data, dataSize);
            break;
        case HashAlgorithm::SHA384:
            CC_SHA384_Update(&sha384_ctx, data, dataSize);
            break;
        case HashAlgorithm::SHA512:
            CC_SHA512_Update(&sha512_ctx, data, dataSize);
            break;
    }

    return true;
}

bool macOSHash::Final(std::vector<unsigned char>& digest) {
    if (!isInitialized) {
        return false;
    }

    switch (currentAlgorithm) {
        case HashAlgorithm::MD5:
            digest.resize(CC_MD5_DIGEST_LENGTH);
            CC_MD5_Final(digest.data(), &md5_ctx);
            break;
        case HashAlgorithm::SHA1:
            digest.resize(CC_SHA1_DIGEST_LENGTH);
            CC_SHA1_Final(digest.data(), &sha1_ctx);
            break;
        case HashAlgorithm::SHA256:
            digest.resize(CC_SHA256_DIGEST_LENGTH);
            CC_SHA256_Final(digest.data(), &sha256_ctx);
            break;
        case HashAlgorithm::SHA384:
            digest.resize(CC_SHA384_DIGEST_LENGTH);
            CC_SHA384_Final(digest.data(), &sha384_ctx);
            break;
        case HashAlgorithm::SHA512:
            digest.resize(CC_SHA512_DIGEST_LENGTH);
            CC_SHA512_Final(digest.data(), &sha512_ctx);
            break;
    }

    isInitialized = false;
    return true;
}

