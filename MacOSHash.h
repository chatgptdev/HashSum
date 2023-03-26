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

#ifndef MACOS_HASH_H
#define MACOS_HASH_H

#include <string>
#include <vector>
#include <CommonCrypto/CommonDigest.h>

class macOSHash {
public:
    macOSHash();
    ~macOSHash();

    bool Init(const std::string& algorithm);
    bool Update(const unsigned char* data, size_t dataSize);
    bool Final(std::vector<unsigned char>& digest) ;
  
    static std::vector<std::string> GetSupportedAlgorithms()
    {
      std::vector<std::string> supportedAlgorithms;

      supportedAlgorithms.push_back("md5");
      supportedAlgorithms.push_back("sha1");
      supportedAlgorithms.push_back("sha256");
      supportedAlgorithms.push_back("sha384");
      supportedAlgorithms.push_back("sha512");

      return supportedAlgorithms;
    }

private:
    CC_MD5_CTX md5_ctx;
    CC_SHA1_CTX sha1_ctx;
    CC_SHA256_CTX sha256_ctx;
    CC_SHA512_CTX sha384_ctx;
    CC_SHA512_CTX sha512_ctx;

    enum HashAlgorithm {
        MD5, SHA1, SHA256, SHA384, SHA512
    };

    HashAlgorithm currentAlgorithm;
    bool isInitialized;
};

#endif // MACOS_HASH_H
