#include <crypto/encryption.hpp>
#include <utils/codec.hpp>
#include <iostream>
#include <stdexcept>

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class F> void rejects(F operation, const char* message) {
    try { operation(); } catch (const std::exception&) { return; }
    throw std::runtime_error(message);
}

void test_encryption_and_keys() {
    Encryption alice, bob, stranger;
    auto key = alice.generate_aes_key();
    const std::vector<unsigned char> text{'h', 'e', 'l', 'l', 'o'};
    const auto encrypted = alice.encrypt_with_aes(key, text);
    check(bob.decrypt_with_aes(key, encrypted) == text, "AES round trip failed");
    check(bob.decrypt_with_aes(key, alice.encrypt_with_aes(key, {})).empty(), "Empty plaintext failed");
    for (std::size_t i = 0; i < encrypted.size(); ++i) {
        auto tampered = encrypted;
        tampered[i] ^= 1;
        rejects([&] { bob.decrypt_with_aes(key, tampered); }, "Tampered GCM frame accepted");
    }
    for (std::size_t length = 0; length < 28; ++length)
        rejects([&] { bob.decrypt_with_aes(key, std::vector<unsigned char>(length)); }, "Short frame accepted");
    for (std::size_t length : {0, 1, 31, 33}) {
        const std::vector<unsigned char> invalid_key(length);
        rejects([&] { alice.encrypt_with_aes(invalid_key, text); }, "Invalid encryption key accepted");
        rejects([&] { alice.decrypt_with_aes(invalid_key, encrypted); }, "Invalid decryption key accepted");
        rejects([&] { Encryption::derive_session_key(key, invalid_key); }, "Invalid session secret accepted");
    }

    const auto bob_pem = bob.get_public_key_bytes();
    const auto pin = bob.get_public_key_fingerprint();
    rejects([&] { alice.load_peer_public_key(bob_pem, ""); }, "Untrusted public key accepted");
    rejects([&] { alice.load_peer_public_key(stranger.get_public_key_bytes(), pin); }, "Substituted key accepted");
    rejects([&] { alice.load_peer_public_key(text, pin); }, "Invalid PEM accepted");
    for (int i = 0; i < 200; ++i) alice.load_peer_public_key(bob_pem, pin);
    rejects([&] { alice.load_peer_public_key(stranger.get_public_key_bytes(), pin); }, "Wrong fingerprint accepted");
    auto encrypted_key = alice.encrypt_with_peer_public_key(key);
    check(bob.decrypt_with_private_key(encrypted_key) == key, "RSA round trip or retained peer key failed");
    rejects([&] { stranger.decrypt_with_private_key(encrypted_key); }, "RSA decryption failure ignored");
    encrypted_key[0] ^= 1;
    rejects([&] { bob.decrypt_with_private_key(encrypted_key); }, "Invalid OAEP accepted");
    rejects([&] { bob.decrypt_with_private_key({}); }, "Empty RSA ciphertext accepted");

    for (std::size_t length = 0; length < 100; ++length) {
        std::vector<unsigned char> bytes(length);
        for (std::size_t i = 0; i < length; ++i) bytes[i] = static_cast<unsigned char>(i);
        check(codec::base64_decode(codec::base64_encode(bytes)) == bytes, "Base64 round trip failed");
    }
    for (const std::string invalid : {"a", "!!!!", "AA=A", "====", "Zh==", "not-a-key"})
        rejects([&] { codec::base64_decode(invalid); }, "Malformed Base64 accepted");
}

}

int main() {
    try {
        test_encryption_and_keys();
        std::cout << "Проверки шифрования и ключей пройдены\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
