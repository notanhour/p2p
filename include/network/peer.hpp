#pragma once

#include <utility>
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>
#include <crypto/encryption.hpp>
#include <storage/state.hpp>

namespace asio = boost::asio;
using boost::asio::ip::tcp;
using json = nlohmann::json;

namespace network {

enum class OutputKind { info, success, warning, error, message };

class Connection : public std::enable_shared_from_this<Connection> {
private:
    tcp::socket socket;
    tcp::resolver resolver;
    asio::steady_timer deadline;
    asio::steady_timer resolve_ready;
    asio::steady_timer confirmation_ready;
    std::optional<bool> trust_decision;
    tcp::resolver::results_type resolved_endpoints;
    boost::system::error_code resolve_error;
    asio::streambuf receive_buffer;
    std::vector<unsigned char> aes_key;
    std::string peer_nickname;
    std::string peer_endpoint;
    std::string peer_fingerprint;
    unsigned short peer_port = 0;
    std::size_t deadline_generation = 0;
    bool closed = false;
    bool writing = false;
    bool ready = false;
    bool timed_out = false;

public:
    // Лимит включает перевод строки и действует для входящих и исходящих кадров.
    static constexpr std::size_t max_frame_size = 64 * 1024;
    explicit Connection(tcp::socket socket);
    ~Connection();

    tcp::socket& get_socket();
    asio::awaitable<tcp::resolver::results_type> resolve(std::string host, unsigned short port);
    const std::vector<unsigned char>& get_aes_key() const;
    void set_aes_key(const std::vector<unsigned char>& key);
    const std::string& get_peer_nickname() const;
    void set_peer_nickname(const std::string& nickname);
    void set_peer_identity(const std::string& endpoint, const std::string& fingerprint, unsigned short port);
    const std::string& get_peer_endpoint() const;
    const std::string& get_peer_fingerprint() const;
    unsigned short get_peer_port() const;
    void prepare_confirmation();
    void confirm(bool trusted);
    asio::awaitable<bool> wait_for_confirmation();
    bool is_ready() const;
    void mark_ready();
    bool has_timed_out() const;
    void ensure_open() const;
    void start_deadline(std::chrono::steady_clock::duration timeout);
    void stop_deadline();

    asio::awaitable<std::string> read_line();
    asio::awaitable<void> write_line(std::string line);
    asio::awaitable<void> write_pem_data(const std::vector<unsigned char>& data);
    asio::awaitable<std::vector<unsigned char>> read_pem_data(const std::string& data);
    void close();
};

class Peer {
private:
    std::string host;
    unsigned short port;
    asio::io_context& io_context;
    asio::strand<asio::io_context::executor_type> executor;
    tcp::acceptor acceptor;
    std::shared_ptr<Connection> connection;
    std::unordered_set<std::shared_ptr<Connection>> active_connections;
    Encryption encryption;
    storage::KnownPeers known_peers;
    std::string nickname;
    std::string public_key_fingerprint;
    std::string initial_fingerprint;
    std::shared_ptr<Connection> pending_confirmation;
    std::function<void(const std::string&, const std::string&)> trust_request_handler;
    std::function<void()> trust_end_handler;
    std::function<void(const std::string&, OutputKind)> output_handler;
    std::atomic<bool> closed{false};

    void release_connection(const std::shared_ptr<Connection>& session);
    void output(const std::string& text, OutputKind kind = OutputKind::info);
    asio::awaitable<void> accept_connections();
    asio::awaitable<void> handle_new_connection(std::shared_ptr<Connection> session);
    asio::awaitable<void> handle_peer(std::shared_ptr<Connection> session);
    asio::awaitable<void> send_on(std::shared_ptr<Connection> session, json message);
    asio::awaitable<void> exchange_nicknames(std::shared_ptr<Connection> session);
    asio::awaitable<void> send_public_key(std::shared_ptr<Connection> session);
    asio::awaitable<std::vector<unsigned char>> read_public_key(
        std::shared_ptr<Connection> session, std::string frame, std::optional<unsigned short> target_port = {});
    asio::awaitable<void> authenticate_peer(std::shared_ptr<Connection> session,
                                          std::vector<unsigned char> public_key);

public:
    static constexpr unsigned short default_port = 42000;
    static constexpr auto handshake_timeout = std::chrono::seconds(5);
    static constexpr auto trust_timeout = std::chrono::seconds(60);
    Peer(const std::string& host, unsigned short port, asio::io_context& io_context,
         const std::string& trusted_fingerprint = "", const std::filesystem::path& data_directory = {});

    // Запускайте публичные корутины на этом исполнителе: он управляет всем состоянием сессии.
    asio::strand<asio::io_context::executor_type> get_executor() const;
    void start();
    // Можно вызывать из любого потока. Очистка передается исполнителю ввода-вывода.
    void close();
    std::string get_nickname() const;
    std::string get_public_key_fingerprint() const;
    // Задаем обработчик до запуска ввода-вывода. Подтверждения и команды доверия выполняем на исполнителе пира.
    void set_trust_request_handler(std::function<void(const std::string&, const std::string&)> handler,
                                  std::function<void()> end_handler = {});
    void set_output_handler(std::function<void(const std::string&, OutputKind)> handler);
    void confirm_peer(bool trusted);
    void trust_peer(const std::string& host, unsigned short port, const std::string& fingerprint);

    asio::awaitable<void> send_message(const json& message);
    asio::awaitable<boost::system::error_code> connect_to_peer(const std::string& peer_host, unsigned short peer_port);
    asio::awaitable<void> initiate_disconnect();
    asio::awaitable<bool> check_peer(const std::string& host, unsigned short port);
};

}
