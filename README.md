# HashSum
C++ program written almost entirely by ChatGPT 4.0 to calculate the hash of files in a given directory and its subdirectories and outputing the resulat in a format similar to SHASUM tool.
The program is designed to be fast and efficient, taking advantage of multi-threading to process multiple files in parallel.

## Features

- Computes hash for all files in a given directory and its subdirectories
- Supports various hash algorithms, including SHA256 (default), SHA1, SHA512, MD5, etc.
- Multithreaded implementation for faster processing on systems with multiple CPU cores
- Can handle both file and directory input paths
- Outputs the hash and relative file paths in a user-friendly format
- Can write the output to a file or print it to the terminal

## Implementation

The program uses C++17 features and the following libraries:

- Standard Library `<filesystem>` for directory traversal and file manipulation
- OpenSSL for computing the hash values

A custom thread pool implementation is used to manage and distribute the work among multiple threads.

## Building and Running on Linux, macOS, and Windows

### Prerequisites

- A C++17 compliant compiler (GCC, Clang, or MSVC)
- OpenSSL development libraries
- CMake (version 3.10 or later)

### Building

1. Clone the repository:
```
git clone https://github.com/chatgptdev/HashSum.git
cd HashSum
```

2. Create a build directory and run CMake:
```
mkdir build
cd build
cmake ..
```

3. Build the project:
```
cmake --build .
```

### Running

After building the project, you can run the program with the following command:

```
./hashSum [input_path] [-a hash_algorithm] [-o output_path]
```

- `input_path`: The path to the directory or file you want to compute the hash for (mandatory)
- `hash_algorithm`: The hash algorithm to use, e.g., "SHA256", "SHA1", "SHA512", "MD5" (optional, default: "SHA256")
- `output_path`: The path to the file where the output will be written (optional, if not specified, the output will be printed to the terminal)

Example:
```
./hashSum /path/to/directory -a SHA256 -o output.txt
```


