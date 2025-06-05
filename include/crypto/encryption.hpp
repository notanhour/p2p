#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

class Encryption {
private:
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY* peer_pkey = nullptr;

public:
    Encryption();
    ~Encryption();
    
    std::vector<unsigned char> get_public_key_bytes();
    void load_peer_public_key(const std::vector<unsigned char>& public_key_bytes);
    
    std::vector<unsigned char> encrypt_with_peer_public_key(const std::vector<unsigned char>& data);
    std::vector<unsigned char> decrypt_with_private_key(const std::vector<unsigned char>& encrypted_data);

    std::vector<unsigned char> generate_aes_key();
    
    std::vector<unsigned char> encrypt_with_aes(const std::vector<unsigned char>& key, const std::vector<unsigned char>& plaintext);
    std::vector<unsigned char> decrypt_with_aes(const std::vector<unsigned char>& key, const std::vector<unsigned char>& encrypted_data);
};

#endif