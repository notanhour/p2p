#pragma once

#include <filesystem>
#include <map>
#include <optional>
#include <string>

namespace storage {

void prepare_directory(const std::filesystem::path& directory);
std::optional<std::string> read_file(const std::filesystem::path& path);
// Записываем файл целиком с правами 0600 и атомарно публикуем готовое содержимое.
bool write_file(const std::filesystem::path& path, const std::string& contents, bool replace);
std::string normalize_fingerprint(const std::string& fingerprint);

class KnownPeers {
private:
    std::filesystem::path directory;
    std::map<std::string, std::string> peers;
    std::map<std::string, std::string> load() const;

public:
    explicit KnownPeers(const std::filesystem::path& directory = {});
    std::optional<std::string> find(const std::string& endpoint) const;
    void remember(const std::string& endpoint, const std::string& fingerprint, bool replace = false);
};

}
