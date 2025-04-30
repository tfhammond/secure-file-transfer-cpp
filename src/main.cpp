// src/main.cpp
#include <iostream>
#include "encrypt.hpp"
#include "decrypt.hpp"

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "Usage: encrypt <encrypt|decrypt> <input> <output> <keyfile>\n";
        return 1;
    }
    std::string mode = argv[1];
    std::string in_path = argv[2];
    std::string out_path = argv[3];
    std::string key_path = argv[4];

    bool ok = false;
    if (mode == "encrypt") {
        ok = encrypt_file(in_path, out_path, key_path);
    } else if (mode == "decrypt") {
        ok = decrypt_file(in_path, out_path, key_path);
    } else {
        std::cerr << "Error: unknown mode '" << mode << "'.\n";
        std::cerr << "Usage: encrypt <encrypt|decrypt> <input> <output> <keyfile>\n";
        return 1;
    }

    return ok ? 0 : 2;
}
