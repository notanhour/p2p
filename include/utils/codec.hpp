#ifndef CODEC_HPP
#define CODEC_HPP

#include <string>
#include <vector>
#include <openssl/bio.h>
#include <openssl/evp.h>

namespace codec {

    inline std::string base64_encode(const std::vector<unsigned char>& data) {
        // Настраиваем BIO для кодирования
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bio = BIO_new(BIO_s_mem());
        BIO_push(b64, bio);
        
        // Отключаем добавление переносов строк
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        
        // Записываем данные
        BIO_write(b64, data.data(), static_cast<int>(data.size()));
        BIO_flush(b64);
        
        // Получаем результат из памяти BIO
        char* encoded_data = nullptr;
        long len = BIO_get_mem_data(bio, &encoded_data);
        std::string result(encoded_data, len);
        
        // Отдаем ресурсы системе
        BIO_free_all(b64);
        return result;
    }
    
    inline std::vector<unsigned char> base64_decode(const std::string& encoded) {
        // Настраиваем BIO для декодирования
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bio = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
        BIO_push(b64, bio);
        
        // Отключаем обработку переносов строк
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        
        // Читаем декодированные данные
        std::vector<unsigned char> decoded(encoded.size()); // Достаточный размер
        int len = BIO_read(b64, decoded.data(), static_cast<int>(encoded.size()));
        decoded.resize(std::max(0, len));
        
        // Отдаем ресурсы системе
        BIO_free_all(b64);
        return decoded;
    }

}

#endif