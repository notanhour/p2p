#include <crypto/encryption.hpp>
#include <storage/state.hpp>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class F> void rejects(F operation, const char* message) {
    try { operation(); } catch (const std::exception&) { return; }
    throw std::runtime_error(message);
}

class TemporaryDirectory {
public:
    std::filesystem::path path;
    TemporaryDirectory() {
        std::string pattern = (std::filesystem::temp_directory_path() / "p2p-state-XXXXXX").string();
        if (!mkdtemp(pattern.data())) throw std::runtime_error("Cannot create temporary directory");
        path = pattern;
    }
    ~TemporaryDirectory() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

void check_permissions(const std::filesystem::path& path, unsigned int expected) {
    struct stat info{};
    check(stat(path.c_str(), &info) == 0, "Cannot inspect file permissions");
    check((info.st_mode & 0777) == expected, "Unexpected state permissions");
}

void test_identity() {
    TemporaryDirectory directory;
    const auto path = directory.path / "identity.pem";
    Encryption first(path), second(path);
    check(first.get_public_key_bytes() == second.get_public_key_bytes(), "Identity changed on reload");
    check(first.get_public_key_fingerprint() == second.get_public_key_fingerprint(), "Fingerprint changed on reload");
    check_permissions(path, 0600);
    check_permissions(directory.path, 0700);
    const auto saved = storage::read_file(path);
    check(saved && saved->find("PRIVATE KEY") != std::string::npos, "Identity is not a private PEM key");

    std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                      std::filesystem::perms::group_read);
    rejects([&] { Encryption invalid(path); }, "Private identity with shared permissions accepted");
    std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
    storage::write_file(path, "invalid private key", true);
    rejects([&] { Encryption invalid(path); }, "Invalid private identity silently replaced");
    check(storage::read_file(path) == "invalid private key", "Invalid identity was overwritten");

    const auto target = directory.path / "target.pem";
    storage::write_file(target, *saved, false);
    std::filesystem::remove(path);
    std::filesystem::create_symlink(target, path);
    rejects([&] { Encryption invalid(path); }, "Identity symbolic link followed");
    check(storage::read_file(target) == saved, "Linked identity was overwritten");
}

void test_concurrent_identity_creation() {
    TemporaryDirectory directory;
    const auto path = directory.path / "identity.pem";
    std::string fingerprints[2];
    std::exception_ptr failures[2];
    auto worker = [&](int index) {
        try {
            Encryption identity(path);
            fingerprints[index] = identity.get_public_key_fingerprint();
        } catch (...) { failures[index] = std::current_exception(); }
    };
    std::thread first(worker, 0), second(worker, 1);
    first.join();
    second.join();
    for (const auto& failure : failures) if (failure) std::rethrow_exception(failure);
    check(fingerprints[0] == fingerprints[1], "Concurrent launches created different identities");
    for (const auto& entry : std::filesystem::directory_iterator(directory.path))
        check(entry.path().filename() == "identity.pem", "Temporary key file was not removed");
}

void test_known_peers() {
    TemporaryDirectory directory;
    const std::string alice(64, 'a'), bob(64, 'b');
    storage::KnownPeers peers(directory.path);
    check(!peers.find("127.0.0.1:8080"), "Unknown peer is already trusted");
    peers.remember("127.0.0.1:8080", alice);
    storage::KnownPeers reloaded(directory.path);
    check(reloaded.find("127.0.0.1:8080") == alice, "Trust was not preserved on reload");
    rejects([&] { reloaded.remember("127.0.0.1:8080", bob); }, "Changed key automatically replaced");
    check(peers.find("127.0.0.1:8080") == alice, "Changed key altered the saved fingerprint");
    reloaded.remember("127.0.0.1:8080", bob, true);
    check(peers.find("127.0.0.1:8080") == bob, "Explicit replacement was not saved");
    const auto path = directory.path / "known_peers";
    check_permissions(path, 0600);
    check(storage::read_file(path) == "127.0.0.1:8080 " + bob + "\n", "Unexpected known_peers text format");
    rejects([&] { peers.remember("127.0.0.1:8081", "invalid"); }, "Invalid fingerprint saved");
    rejects([&] { peers.remember("127.0.0.1:0", alice); }, "Invalid endpoint saved");
    rejects([&] { peers.remember("127.0.0.1:8081\n127.0.0.1:8082", alice); }, "Multiline endpoint saved");
    peers.remember("[0:0:0:0:0:0:0:1]:8080", alice);
    check(peers.find("[::1]:8080") == alice, "IPv6 trust was not normalized");
    peers.remember("127.0.0.1:8081", alice);
    check(peers.find("127.0.0.1:8080") == bob && peers.find("127.0.0.1:8081") == alice,
          "Different ports shared a trusted key");

    // Независимые экземпляры хранилища обновляют записи под общей файловой блокировкой.
    std::exception_ptr failures[2];
    auto worker = [&](int index) {
        try {
            storage::KnownPeers concurrent(directory.path);
            concurrent.remember("127.0.0.1:" + std::to_string(8090 + index), alice);
        } catch (...) { failures[index] = std::current_exception(); }
    };
    std::thread first(worker, 0), second(worker, 1);
    first.join();
    second.join();
    for (const auto& failure : failures) if (failure) std::rethrow_exception(failure);
    check(peers.find("127.0.0.1:8090") == alice && peers.find("127.0.0.1:8091") == alice,
          "Concurrent updates lost a known peer");
    // Проверяем чтение комментариев, пустых строк, табуляции и строки без завершающего переноса.
    storage::write_file(path, "# Доверенные собеседники\n\n127.0.0.1:8080\t" + bob + "\r\n[::1]:8080 " + alice, true);
    check(peers.find("127.0.0.1:8080") == bob && peers.find("[::1]:8080") == alice,
          "Valid known_peers text entries were not loaded");
    for (const auto& contents : {
            std::string("invalid entry"), "127.0.0.1:8080 " + alice + " extra\n",
            "127.0.0.1:0 " + alice + "\n", "localhost:8080 " + alice + "\n",
            "127.0.0.1:8080 " + alice + "\n127.0.0.1:8080 " + bob + "\n",
            "[::1]:8080 " + alice + "\n[0:0:0:0:0:0:0:1]:8080 " + alice + "\n"}) {
        storage::write_file(path, contents, true);
        rejects([&] { storage::KnownPeers invalid(directory.path); }, "Invalid known peers silently reset");
        rejects([&] { peers.remember("127.0.0.1:8081", alice); }, "Invalid known_peers file overwritten");
        check(storage::read_file(path) == contents, "Invalid known_peers file was modified");
    }
}
}

int main() {
    try {
        test_identity();
        test_concurrent_identity_creation();
        test_known_peers();
        std::cout << "Проверки постоянных ключей и хранилища доверия пройдены\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
