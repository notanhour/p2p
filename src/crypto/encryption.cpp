#include <crypto/encryption.hpp>

Encryption::Encryption() {
    // Генерируем пару ключей RSA
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
}
    
Encryption::~Encryption() {
    if (pkey) EVP_PKEY_free(pkey);
    if (peer_pkey) EVP_PKEY_free(peer_pkey);
}

std::vector <unsigned char> Encryption::get_public_key_bytes() {
    BIO* bio = BIO_new(BIO_s_mem()); // Создаем память для хранения ключа
    PEM_write_bio_PUBKEY(bio, pkey); // Записываем открытый ключ в память
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data); // Получаем данные из памяти
    std::vector <unsigned char> result(data, data + len);
    BIO_free(bio);
    return result;
}

void Encryption::load_peer_public_key(const std::vector <unsigned char>& public_key_bytes) {
    BIO* bio = BIO_new_mem_buf(public_key_bytes.data(), public_key_bytes.size()); // Создаем память для хранения открытого ключа
    peer_pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr); // Читаем открытый ключ из памяти
    BIO_free(bio);
}

std::vector <unsigned char> Encryption::encrypt_with_peer_public_key(const std::vector <unsigned char>& data) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(peer_pkey, nullptr);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    size_t len = 0;
    EVP_PKEY_encrypt(ctx, nullptr, &len, data.data(), data.size());
    std::vector<unsigned char> out(len);
    EVP_PKEY_encrypt(ctx, out.data(), &len, data.data(), data.size());
    EVP_PKEY_CTX_free(ctx);
    out.resize(len);
    return out;
}

std::vector <unsigned char> Encryption::decrypt_with_private_key(const std::vector <unsigned char>& encrypted_data) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    size_t len = 0;
    EVP_PKEY_decrypt(ctx, nullptr, &len, encrypted_data.data(), encrypted_data.size());
    std::vector<unsigned char> out(len);
    EVP_PKEY_decrypt(ctx, out.data(), &len, encrypted_data.data(), encrypted_data.size());
    EVP_PKEY_CTX_free(ctx);
    out.resize(len);
    return out;
}

std::vector <unsigned char> Encryption::generate_aes_key() {
    std::vector <unsigned char> key(32);
    RAND_bytes(key.data(), key.size());
    return key;
}

std::vector <unsigned char> Encryption::encrypt_with_aes(const std::vector <unsigned char>& key, const std::vector <unsigned char>& plaintext) {
    // Генерируем случайный IV
    std::vector <unsigned char> iv(12);
    RAND_bytes(iv.data(), iv.size());

    // Настраиваем контекст шифрования
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    // Шифруем данные
    std::vector <unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    // Получаем аутентификационный тег
    std::vector <unsigned char> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data());
    EVP_CIPHER_CTX_free(ctx);

    std::vector <unsigned char> result;
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), tag.begin(), tag.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    return result;
}

std::vector <unsigned char> Encryption::decrypt_with_aes(const std::vector <unsigned char>& key, const std::vector <unsigned char>& encrypted_data) {
    std::vector <unsigned char> iv(encrypted_data.begin(), encrypted_data.begin() + 12);
    std::vector <unsigned char> tag(encrypted_data.begin() + 12, encrypted_data.begin() + 28);
    std::vector <unsigned char> ciphertext(encrypted_data.begin() + 28, encrypted_data.end());

    // Настраиваем контекст дешифрования
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    // Дешифруем данные
    std::vector <unsigned char> plaintext(ciphertext.size());
    int len = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    int plaintext_len = len;

    // Задаем тег для проверки целостности
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data());
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}