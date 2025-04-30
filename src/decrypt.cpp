#include "decrypt.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <vector>
#include <iostream>

// AES-GCM 
static constexpr int KEY_LEN = 32;   // 256 bits
static constexpr int IV_LEN  = 12;   // recommended for GCM
static constexpr int TAG_LEN = 16;   // 128-bit tag

bool decrypt_file(const std::string& in_path, const std::string& out_path, const std::string& key_path) {

    //Load key and IV from the key file
    std::ifstream kf(key_path, std::ios::binary);
    if (!kf) {
        std::cerr << "Error: cannot open key file '" << key_path << "'" << std::endl;
        return false;
    }
    std::istreambuf_iterator<char> kit(kf);//Iterate all bytes from key file
    std::istreambuf_iterator<char> kend;
    std::vector<uint8_t> key_iv(kit, kend); //buffer
    kf.close();


    if (key_iv.size() != KEY_LEN + IV_LEN) { //Check the size before decrypting
        std::cerr << "Error: key file size is incorrect. Expected Bytes: " << (KEY_LEN + IV_LEN) << std::endl;
        return false;
    }

    //Break up into key and IV 
    std::vector<uint8_t> key(key_iv.begin(), key_iv.begin() + KEY_LEN);
    std::vector<uint8_t> iv(key_iv.begin() + KEY_LEN, key_iv.end());

    //Load ciphertext and tag from input file
    std::ifstream inpf(in_path, std::ios::binary);
    if (!inpf) {
        std::cerr << "Error: cannot open inpuyt file '" << in_path << "'" << std::endl;
        return false;
    }
    std::istreambuf_iterator<char> cit(inpf);
    std::istreambuf_iterator<char> cend;
    std::vector<uint8_t> cbuf(cit, cend); //buffer 
    inpf.close();

    if (cbuf.size() < TAG_LEN) {
        std::cerr << "Error: input file too small to contain tag" << std::endl;
        return false;
    }
    size_t cipher_len = cbuf.size() - TAG_LEN;
    std::vector<uint8_t> ciphertext(cbuf.begin(), cbuf.begin() + cipher_len);
    std::vector<uint8_t> tag(cbuf.begin() + cipher_len, cbuf.end());


    //Initialize evp context for the decryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error: EVP_CIPHER_CTX_new has failed" << std::endl;
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { //Initializes for AES 256 in GCM mode
        std::cerr << "Error: EVP_DecryptInit_ex has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) { //set IV length
        std::cerr << "Error: EVP_CIPHER_CTX_ctrl (set IV Length) has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) { // set key and iv for
        std::cerr << "Error: EVP_DecryptInit_ex (set key/iv) has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // decrypt

    std::vector<uint8_t> plaintext(ciphertext.size());
    int out_len1 = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len1, ciphertext.data(), ciphertext.size()) != 1) {
        std::cerr << "Error: EVP_DecryptUpdate has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag.data()) != 1){ //set auth tag
        std::cerr << "Error: EVP_CIPHER_CTX_ctrl (set tag) has failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int out_len2 = 0;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len1, &out_len2);

    EVP_CIPHER_CTX_free(ctx);
    if (ret <= 0) { // could be wrong key or iv or tag
        std::cerr << "Error: decryption failed (AUTHENTICATION ERROR)" << std::endl;
        return false;
    }

    //Write plaintext output file
    std::ofstream of(out_path, std::ios::binary);
    if (!of) {
        std::cerr << "Error: cannot open output file '" << out_path << "'" << std::endl;
        return false;
    }
    of.write(reinterpret_cast<const char*>(plaintext.data()), out_len1 + out_len2);
    of.close();

    std::cout << "DECRYPTED '" << in_path << "' to " << out_path << std::endl;
    return true;

}