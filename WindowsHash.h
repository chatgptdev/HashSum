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

private:
    bool initialized;
    BCRYPT_ALG_HANDLE hAlgorithm;
    BCRYPT_HASH_HANDLE hHash;
};

#endif // WINDOWS_HASH_H
