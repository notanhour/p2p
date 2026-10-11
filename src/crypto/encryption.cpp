#include <crypto/encryption.hpp>
#include <storage/state.hpp>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <climits>
#include <memory>
#include <stdexcept>

namespace {
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;

void require(bool success, const char* message) {
    if (!success) throw std::runtime_error(message);
}

int checked_size(std::size_t size) {
    if (size > INT_MAX) throw std::length_error("Cryptographic input is too large");
    return static_cast<int>(size);
}

void validate_aes_key(const std::vector<unsigned char>& key) {
    require(key.size() == 32, "AES-256 requires a 32-byte key");
}

std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> digest(32);
    unsigned int length = 0;
    require(EVP_Digest(data.data(), data.size(), digest.data(), &length, EVP_sha256(), nullptr) == 1,
            "SHA-256 failed");
    require(length == digest.size(), "Invalid SHA-256 output");
    return digest;
}

std::string fingerprint(EVP_PKEY* key) {
    int length = i2d_PUBKEY(key, nullptr);
    require(length > 0, "Cannot encode public key");
    std::vector<unsigned char> der(length);
    auto* output = der.data();
    require(i2d_PUBKEY(key, &output) == length, "Cannot encode public key");
    const auto digest = sha256(der);
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (auto byte : digest) {
        result += hex[byte >> 4];
        result += hex[byte & 15];
    }
    return result;
}

KeyContext rsa_context(EVP_PKEY* key, bool encrypt) {
    require(key != nullptr, "No peer public key installed");
    KeyContext ctx(EVP_PKEY_CTX_new(key, nullptr), EVP_PKEY_CTX_free);
    require(ctx != nullptr, "Cannot allocate RSA context");
    require((encrypt ? EVP_PKEY_encrypt_init(ctx.get()) : EVP_PKEY_decrypt_init(ctx.get())) == 1,
            "Cannot initialize RSA");
    require(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) == 1 &&
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) == 1 &&
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) == 1, "Cannot configure RSA OAEP");
    return ctx;
}

Key read_public_key(const std::vector<unsigned char>& bytes) {
    require(!bytes.empty(), "Empty public key");
    Bio bio(BIO_new_mem_buf(bytes.data(), checked_size(bytes.size())), BIO_free);
    require(bio != nullptr, "Cannot allocate public key buffer");
    Key key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    require(key != nullptr && EVP_PKEY_base_id(key.get()) == EVP_PKEY_RSA &&
            EVP_PKEY_bits(key.get()) >= 2048 && EVP_PKEY_bits(key.get()) <= 4096,
            "Invalid RSA public key (expected 2048–4096 bits)");
    return key;
}

Key read_identity(const std::string& pem) {
    Bio bio(BIO_new_mem_buf(pem.data(), checked_size(pem.size())), BIO_free);
    require(bio != nullptr, "Cannot allocate private key buffer");
    Key key(PEM_read_bio_PrivateKey(bio.get(), nullptr,
        [](char*, int, int, void*) { return 0; }, nullptr), EVP_PKEY_free);
    require(key != nullptr && EVP_PKEY_base_id(key.get()) == EVP_PKEY_RSA &&
            EVP_PKEY_bits(key.get()) >= 2048 && EVP_PKEY_bits(key.get()) <= 4096,
            "Invalid RSA identity file");
    KeyContext ctx(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
    require(ctx != nullptr && EVP_PKEY_private_check(ctx.get()) == 1, "Invalid RSA private key");
    return key;
}
}

Encryption::Encryption(const std::filesystem::path& identity_file) {
    if (!identity_file.empty()) {
        storage::prepare_directory(identity_file.parent_path());
        if (auto contents = storage::read_file(identity_file)) {
            pkey = read_identity(*contents).release();
            return;
        }
    }
    KeyContext ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    require(ctx != nullptr, "Cannot allocate RSA context");
    require(EVP_PKEY_keygen_init(ctx.get()) == 1 &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) == 1, "Cannot initialize RSA key generation");
    EVP_PKEY* generated = nullptr;
    const int result = EVP_PKEY_keygen(ctx.get(), &generated);
    Key key(generated, EVP_PKEY_free);
    require(result == 1 && key != nullptr, "Cannot generate RSA key");
    if (!identity_file.empty()) {
        Bio bio(BIO_new(BIO_s_mem()), BIO_free);
        require(bio != nullptr && PEM_write_bio_PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1,
                "Cannot export private key");
        char* data = nullptr;
        const long length = BIO_get_mem_data(bio.get(), &data);
        require(length > 0, "Empty private key");
        const std::string contents(data, length);
        if (!storage::write_file(identity_file, contents, false)) {
            const auto saved = storage::read_file(identity_file);
            require(saved.has_value(), "Identity file disappeared");
            key = read_identity(*saved);
        }
    }
    pkey = key.release();
}

Encryption::~Encryption() {
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer_pkey);
}

std::vector<unsigned char> Encryption::get_public_key_bytes() const {
    Bio bio(BIO_new(BIO_s_mem()), BIO_free);
    require(bio != nullptr && PEM_write_bio_PUBKEY(bio.get(), pkey) == 1, "Cannot export public key");
    char* data = nullptr;
    long length = BIO_get_mem_data(bio.get(), &data);
    require(length > 0, "Empty public key");
    return {data, data + length};
}

std::string Encryption::get_public_key_fingerprint() const {
    return fingerprint(pkey);
}

std::string Encryption::public_key_fingerprint(const std::vector<unsigned char>& bytes) {
    auto key = read_public_key(bytes);
    return fingerprint(key.get());
}

void Encryption::load_peer_public_key(const std::vector<unsigned char>& bytes, const std::string& trusted_fingerprint) {
    auto candidate = read_public_key(bytes);
    const auto actual = fingerprint(candidate.get());
    require(trusted_fingerprint.size() == actual.size() &&
            CRYPTO_memcmp(actual.data(), trusted_fingerprint.data(), actual.size()) == 0,
            "Peer fingerprint is not trusted; exchange fingerprints over a trusted channel and use trust");
    EVP_PKEY_free(peer_pkey);
    peer_pkey = candidate.release();
}

std::vector<unsigned char> Encryption::encrypt_with_peer_public_key(const std::vector<unsigned char>& data) {
    auto ctx = rsa_context(peer_pkey, true);
    std::size_t length = 0;
    require(EVP_PKEY_encrypt(ctx.get(), nullptr, &length, data.data(), data.size()) == 1, "RSA encryption failed");
    std::vector<unsigned char> output(length);
    require(EVP_PKEY_encrypt(ctx.get(), output.data(), &length, data.data(), data.size()) == 1, "RSA encryption failed");
    output.resize(length);
    return output;
}

std::vector<unsigned char> Encryption::decrypt_with_private_key(const std::vector<unsigned char>& data) {
    require(data.size() == static_cast<std::size_t>(EVP_PKEY_size(pkey)), "Invalid RSA ciphertext length");
    auto ctx = rsa_context(pkey, false);
    std::size_t length = 0;
    require(EVP_PKEY_decrypt(ctx.get(), nullptr, &length, data.data(), data.size()) == 1, "RSA decryption failed");
    std::vector<unsigned char> output(length);
    if (EVP_PKEY_decrypt(ctx.get(), output.data(), &length, data.data(), data.size()) != 1) {
        OPENSSL_cleanse(output.data(), output.size());
        throw std::runtime_error("RSA decryption failed");
    }
    output.resize(length);
    return output;
}

std::vector<unsigned char> Encryption::generate_aes_key() {
    std::vector<unsigned char> key(32);
    require(RAND_bytes(key.data(), checked_size(key.size())) == 1, "Cannot generate session key");
    return key;
}

std::vector<unsigned char> Encryption::derive_session_key(const std::vector<unsigned char>& initiator,
                                                         const std::vector<unsigned char>& responder) {
    validate_aes_key(initiator);
    validate_aes_key(responder);
    const std::string label = "p2p session";
    std::vector<unsigned char> input(label.begin(), label.end());
    input.insert(input.end(), initiator.begin(), initiator.end());
    input.insert(input.end(), responder.begin(), responder.end());
    auto key = sha256(input);
    OPENSSL_cleanse(input.data(), input.size());
    return key;
}

std::vector<unsigned char> Encryption::encrypt_with_aes(const std::vector<unsigned char>& key,
                                                      const std::vector<unsigned char>& plaintext) {
    validate_aes_key(key);
    const int input_length = checked_size(plaintext.size());
    std::vector<unsigned char> result(28 + plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    require(RAND_bytes(result.data(), 12) == 1, "Cannot generate IV");
    CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    require(ctx != nullptr && EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), result.data()) == 1,
            "Cannot initialize AES-GCM encryption");
    int length = 0;
    require(EVP_EncryptUpdate(ctx.get(), result.data() + 28, &length, plaintext.data(), input_length) == 1,
            "AES-GCM encryption failed");
    int total = length;
    require(EVP_EncryptFinal_ex(ctx.get(), result.data() + 28 + total, &length) == 1, "AES-GCM encryption failed");
    total += length;
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, result.data() + 12) == 1,
            "Cannot obtain AES-GCM tag");
    result.resize(28 + total);
    return result;
}

std::vector<unsigned char> Encryption::decrypt_with_aes(const std::vector<unsigned char>& key,
                                                      const std::vector<unsigned char>& data) {
    validate_aes_key(key);
    require(data.size() >= 28, "Encrypted frame is shorter than its IV and tag");
    const int input_length = checked_size(data.size() - 28);
    CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    require(ctx != nullptr && EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), data.data()) == 1,
            "Cannot initialize AES-GCM decryption");
    std::vector<unsigned char> plaintext(data.size() - 28 + EVP_MAX_BLOCK_LENGTH);
    int length = 0;
    require(EVP_DecryptUpdate(ctx.get(), plaintext.data(), &length, data.data() + 28, input_length) == 1,
            "AES-GCM decryption failed");
    int total = length;
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(data.data() + 12)) == 1,
            "Cannot set AES-GCM tag");
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total, &length) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw std::runtime_error("AES-GCM authentication failed");
    }
    plaintext.resize(total + length);
    return plaintext;
}
