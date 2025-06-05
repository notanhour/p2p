#ifndef PEER_HPP
#define PEER_HPP

#include <iostream>
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <utility>
#include <atomic>
#include <crypto/encryption.hpp>

namespace asio = boost::asio;
using boost::asio::ip::tcp;
using json = nlohmann::json;

namespace network {

    class Connection {
    private:
        tcp::socket socket;
        std::vector<unsigned char> aes_key;
        std::string peer_nickname;

    public:
        explicit Connection(tcp::socket socket);
        ~Connection();

        tcp::socket& get_socket();

        const std::vector<unsigned char>& get_aes_key() const;
        void set_aes_key(const std::vector<unsigned char>& key);

        const std::string& get_peer_nickname() const;
        void set_peer_nickname(const std::string& nickname);

        asio::awaitable<std::string> read_line();
        asio::awaitable<void> write_line(const std::string& line);
        
        asio::awaitable<void> write_pem_data(const std::vector<unsigned char>& data);
        asio::awaitable<std::vector<unsigned char>> read_pem_data(const std::string& data);

        void close();
    };

    class Peer {
    private:
        std::string host;
        unsigned short port;
        asio::io_context& io_context;
        tcp::acceptor acceptor;
        std::unique_ptr<Connection> connection;
        Encryption encryption;
        std::string nickname;
        std::thread io_thread;
        std::atomic<bool> closed{false};

        asio::awaitable<void> accept_connections();
        asio::awaitable<void> handle_new_connection(tcp::socket socket);
        asio::awaitable<void> handle_peer();

    public:
        Peer(const std::string& host, unsigned short port, asio::io_context& io_context);

        void start();
        void close();

        std::string get_nickname();

        asio::awaitable<void> send_message(const json& message);
        asio::awaitable<boost::system::error_code> connect_to_peer(const std::string& peer_host, unsigned short peer_port);
        asio::awaitable<void> initiate_disconnect();

        asio::awaitable<bool> check_peer(const std::string& host, unsigned short port);
        asio::awaitable<std::vector<std::pair<std::string, int>>> discover_peers(unsigned short start_port, unsigned short end_port);
    };

}

#endif