#include <storage/state.hpp>
#include <utils/endpoint.hpp>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <fcntl.h>
#include <sstream>
#include <stdexcept>
#include <sys/file.h>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace storage {
namespace {
class Descriptor {
private:
    int fd;
public:
    explicit Descriptor(int fd) : fd(fd) {
        if (fd < 0) throw std::system_error(errno, std::generic_category(), "Cannot open state file");
    }
    ~Descriptor() { ::close(fd); }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    int get() const { return fd; }
};

void check_file(int fd) {
    struct stat info{};
    if (fstat(fd, &info) != 0) throw std::system_error(errno, std::generic_category(), "Cannot inspect state file");
    if (!S_ISREG(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 0077) != 0)
        throw std::runtime_error("State files must be regular files owned by the current user with permissions 0600");
}

class FileLock {
private:
    Descriptor fd;
public:
    explicit FileLock(const std::filesystem::path& path)
        : fd(open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600)) {
        check_file(fd.get());
        while (flock(fd.get(), LOCK_EX) != 0) {
            if (errno != EINTR) throw std::system_error(errno, std::generic_category(), "Cannot lock known peers");
        }
    }
};
}

void prepare_directory(const std::filesystem::path& directory) {
    if (directory.empty()) return;
    std::filesystem::create_directories(directory);
    struct stat info{};
    if (lstat(directory.c_str(), &info) != 0)
        throw std::system_error(errno, std::generic_category(), "Cannot inspect data directory");
    if (!S_ISDIR(info.st_mode) || info.st_uid != geteuid())
        throw std::runtime_error("Data directory must be owned by the current user and must not be a symbolic link");
    std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
}

std::optional<std::string> read_file(const std::filesystem::path& path) {
    const int opened = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (opened < 0 && errno == ENOENT) return std::nullopt;
    Descriptor fd(opened);
    check_file(fd.get());
    std::string contents;
    char buffer[4096];
    while (true) {
        const auto length = read(fd.get(), buffer, sizeof(buffer));
        if (length == 0) return contents;
        if (length < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "Cannot read state file");
        }
        if (contents.size() + static_cast<std::size_t>(length) > 1024 * 1024)
            throw std::length_error("State file exceeds 1 MiB");
        contents.append(buffer, length);
    }
}

bool write_file(const std::filesystem::path& path, const std::string& contents, bool replace) {
    std::string pattern = (path.parent_path() / ".state-XXXXXX").string();
    std::vector<char> name(pattern.begin(), pattern.end());
    name.push_back('\0');
    Descriptor fd(mkstemp(name.data()));
    const std::filesystem::path temporary(name.data());
    try {
        if (fchmod(fd.get(), 0600) != 0)
            throw std::system_error(errno, std::generic_category(), "Cannot set state file permissions");
        std::size_t offset = 0;
        while (offset < contents.size()) {
            const auto length = write(fd.get(), contents.data() + offset, contents.size() - offset);
            if (length < 0 && errno == EINTR) continue;
            if (length <= 0) throw std::system_error(errno, std::generic_category(), "Cannot write state file");
            offset += length;
        }
        if (fsync(fd.get()) != 0) throw std::system_error(errno, std::generic_category(), "Cannot sync state file");
        if (replace) {
            std::filesystem::rename(temporary, path);
            return true;
        }
        // Жесткая ссылка позволяет двум процессам создать один ключ без перезаписи и частичных файлов.
        if (link(temporary.c_str(), path.c_str()) != 0) {
            if (errno != EEXIST) throw std::system_error(errno, std::generic_category(), "Cannot publish state file");
            std::filesystem::remove(temporary);
            return false;
        }
        std::filesystem::remove(temporary);
        return true;
    } catch (...) {
        std::error_code ec;
        std::filesystem::remove(temporary, ec);
        throw;
    }
}

std::string normalize_fingerprint(const std::string& fingerprint) {
    if (fingerprint.size() != 64 || !std::all_of(fingerprint.begin(), fingerprint.end(), [](unsigned char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    })) throw std::invalid_argument("Expected a 64-digit SHA-256 fingerprint");
    auto result = fingerprint;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return result;
}

KnownPeers::KnownPeers(const std::filesystem::path& directory) : directory(directory) {
    prepare_directory(directory);
    if (!directory.empty()) peers = load();
}

std::map<std::string, std::string> KnownPeers::load() const {
    if (directory.empty()) return peers;
    const auto contents = read_file(directory / "known_peers");
    if (!contents) return {};
    std::map<std::string, std::string> result;
    std::istringstream input(*contents);
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        std::istringstream entry(line);
        std::string endpoint, fingerprint, extra;
        if (!(entry >> endpoint) || endpoint.front() == '#') continue;
        try {
            if (!(entry >> fingerprint) || (entry >> extra)) throw std::runtime_error("Expected address:port and fingerprint");
            if (!result.emplace(endpoints::normalize_numeric(endpoint), normalize_fingerprint(fingerprint)).second)
                throw std::runtime_error("Duplicate peer address");
        } catch (const std::exception& error) {
            throw std::runtime_error("Invalid known_peers entry at line " + std::to_string(line_number) + ": " + error.what());
        }
    }
    return result;
}

std::optional<std::string> KnownPeers::find(const std::string& endpoint) const {
    const auto current = load();
    const auto found = current.find(endpoints::normalize_numeric(endpoint));
    if (found == current.end()) return std::nullopt;
    return found->second;
}

void KnownPeers::remember(const std::string& endpoint, const std::string& fingerprint, bool replace) {
    const auto address = endpoints::normalize_numeric(endpoint);
    const auto normalized = normalize_fingerprint(fingerprint);
    const auto update = [&] {
        auto current = load();
        const auto found = current.find(address);
        if (found != current.end() && found->second == normalized) return;
        if (found != current.end() && found->second != normalized && !replace)
            throw std::runtime_error("Peer key changed for " + address);
        current[address] = normalized;
        if (!directory.empty()) {
            std::ostringstream contents;
            for (const auto& [saved_endpoint, saved_fingerprint] : current)
                contents << saved_endpoint << ' ' << saved_fingerprint << '\n';
            write_file(directory / "known_peers", contents.str(), true);
        }
        peers = std::move(current);
    };
    if (directory.empty()) {
        update();
    } else {
        FileLock lock(directory / ".known_peers.lock");
        update();
    }
}
}
