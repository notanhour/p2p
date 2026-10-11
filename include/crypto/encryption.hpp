#pragma once

#include <openssl/evp.h>
#include <filesystem>
#include <string>
#include <vector>

class Encryption {
private:
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY* peer_pkey = nullptr;

public:
    explicit Encryption(const std::filesystem::path& identity_file = {});
    ~Encryption();
    Encryption(const Encryption&) = delete;
    Encryption& operator=(const Encryption&) = delete;

    std::vector<unsigned char> get_public_key_bytes() const;
    std::string get_public_key_fingerprint() const;
    static std::string public_key_fingerprint(const std::vector<unsigned char>& public_key_bytes);
    void load_peer_public_key(const std::vector<unsigned char>& public_key_bytes,
                              const std::string& trusted_fingerprint);

    std::vector<unsigned char> encrypt_with_peer_public_key(const std::vector<unsigned char>& data);
    std::vector<unsigned char> decrypt_with_private_key(const std::vector<unsigned char>& encrypted_data);
    std::vector<unsigned char> generate_aes_key();
    static std::vector<unsigned char> derive_session_key(const std::vector<unsigned char>& initiator_secret,
                                                       const std::vector<unsigned char>& responder_secret);
    std::vector<unsigned char> encrypt_with_aes(const std::vector<unsigned char>& key, const std::vector<unsigned char>& plaintext);
    std::vector<unsigned char> decrypt_with_aes(const std::vector<unsigned char>& key, const std::vector<unsigned char>& encrypted_data);
};
