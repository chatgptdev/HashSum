
#ifndef MACOS_HASH_H
#define MACOS_HASH_H

#include <string>
#include <vector>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonDigestSPI.h>

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
    CC_SHA384_CTX sha384_ctx;
    CC_SHA512_CTX sha512_ctx;

    enum HashAlgorithm {
        MD5, SHA1, SHA256, SHA384, SHA512
    };

    HashAlgorithm currentAlgorithm;
    bool isInitialized;
};

#endif // MACOS_HASH_H
