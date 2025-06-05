#include <network/peer.hpp>
#include <network/netscan.hpp>
#include <utils/codec.hpp>
#include <utils/namegen.hpp>

using namespace network;

Connection::Connection(tcp::socket socket) : socket(std::move(socket)) {}

Connection::~Connection() {
    close();
}

void Connection::close() {
    if (socket.is_open()) {
        boost::system::error_code ec;
        socket.shutdown(tcp::socket::shutdown_both, ec);
        socket.close(ec);
    }
    aes_key.clear();
    peer_nickname.clear();
}

tcp::socket& Connection::get_socket() {
    return socket;
}

const std::vector<unsigned char>& Connection::get_aes_key() const {
    return aes_key;
}

void Connection::set_aes_key(const std::vector<unsigned char>& key) {
    aes_key = key;
}

const std::string& Connection::get_peer_nickname() const {
    return peer_nickname;
}

void Connection::set_peer_nickname(const std::string& nickname) {
    peer_nickname = nickname;
}

asio::awaitable<std::string> Connection::read_line() {
    asio::streambuf buf;
    try {
        co_await asio::async_read_until(socket, buf, '\n', asio::use_awaitable);
        std::istream is(&buf);
        std::string line;
        std::getline(is, line);
        co_return line;
    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::eof && e.code() != asio::error::operation_aborted && e.code() != asio::error::connection_reset) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
        throw;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        throw;
    }
}

asio::awaitable<void> Connection::write_line(const std::string& line) {
    try {
        co_await asio::async_write(socket, asio::buffer(line + "\n"), asio::use_awaitable);
    } catch (const std::exception&) {
        throw;
    }
}

asio::awaitable<std::vector<unsigned char>> Connection::read_pem_data(const std::string& encoded_data) {
    try {
        auto decoded = codec::base64_decode(encoded_data);
        std::string decoded_str(decoded.begin(), decoded.end());

        if (decoded_str.find("-----BEGIN PUBLIC KEY-----") == std::string::npos || decoded_str.find("-----END PUBLIC KEY-----") == std::string::npos) {
            std::cerr << "Error: Invalid PEM format" << std::endl;
            throw;
        }
        co_return decoded;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        throw;
    }
}

asio::awaitable<void> Connection::write_pem_data(const std::vector<unsigned char>& data) {
    try {
        std::string encoded = codec::base64_encode(data);
        co_await write_line(encoded);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        throw;
    }
}

Peer::Peer(const std::string& host, unsigned short port, asio::io_context& io_context) : host(host), port(port), io_context(io_context), acceptor(io_context, tcp::endpoint(asio::ip::make_address(host), port)), nickname(namegen::generate()) {}

void Peer::start() {
    auto accept_task = accept_connections();
    asio::co_spawn(io_context, std::move(accept_task), asio::detached);
    std::cout << "Server started on " << host << ":" << port << std::endl;
}

void Peer::close() {
    if (!closed.exchange(true)) {
        if (connection) {
            asio::co_spawn(io_context, initiate_disconnect(), asio::detached);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        io_context.stop();
    }
}

asio::awaitable<void> Peer::accept_connections() {
    while (true) {
        try {
            tcp::socket socket = co_await acceptor.async_accept(asio::use_awaitable);
            auto connection_handler = handle_new_connection(std::move(socket));
            asio::co_spawn(io_context, std::move(connection_handler), asio::detached);
        } catch (const std::exception&) {
            break;
        }
    }
}

asio::awaitable<boost::system::error_code> Peer::connect_to_peer(const std::string& peer_host, unsigned short peer_port) {
    if (connection) {
        co_return asio::error::already_connected;
    }
    
    if (peer_host == host && peer_port == port) {
        co_return asio::error::operation_aborted;
    }

    tcp::resolver resolver(io_context);

    try {
        auto endpoints = co_await resolver.async_resolve(peer_host, std::to_string(peer_port), asio::use_awaitable);
        
        auto socket = tcp::socket(io_context);
        co_await asio::async_connect(socket, endpoints, asio::use_awaitable);
        connection = std::make_unique<Connection>(std::move(socket));

        // Отправляем наш публичный ключ
        auto public_key = encryption.get_public_key_bytes();
        co_await connection->write_pem_data(public_key);

        std::string response = co_await connection->read_line();

        if (response == "Error: Peer already connected") {
            connection->close();
            connection.reset();
            co_return asio::error::already_connected;
        }

        // Получаем публичный ключ пира
        auto peer_public_key = co_await connection->read_pem_data(response);
        encryption.load_peer_public_key(peer_public_key);

        // Генерируем и отправляем AES ключ
        auto aes_key = encryption.generate_aes_key();
        auto encrypted_aes_key = encryption.encrypt_with_peer_public_key(aes_key);
        std::string encoded_aes_key = codec::base64_encode(encrypted_aes_key);
        
        co_await connection->write_line(encoded_aes_key);
        connection->set_aes_key(aes_key);
        
        // Отправляем никнейм
        co_await send_message({
            {"type", "nickname"},
            {"nickname", nickname}
        });

        // Получаем никнейм пира
        std::string encoded_data = co_await connection->read_line();
        auto encrypted_data = codec::base64_decode(encoded_data);
        auto decrypted_data = encryption.decrypt_with_aes(connection->get_aes_key(), encrypted_data);
        auto message = json::parse(decrypted_data);
        if (message["type"] == "nickname") {
            connection->set_peer_nickname(message["nickname"]);
            std::cout << "Connected to " << connection->get_peer_nickname() << " (" << connection->get_socket().remote_endpoint().address().to_string() << ")" << std::endl;
        } else {
            connection->close();
            connection.reset();
            co_return asio::error::operation_aborted;
        }

        auto peer_handler = handle_peer();
        asio::co_spawn(io_context, std::move(peer_handler), asio::detached);
        co_return boost::system::error_code();
    } catch (const std::exception&) {
        if (connection) {
            connection->close();
            connection.reset();
        }
        co_return asio::error::operation_aborted;
    }
}

asio::awaitable<void> Peer::handle_new_connection(tcp::socket socket) {
    auto t_connection = std::make_unique<Connection>(std::move(socket));
    
    try {
        std::string data = co_await t_connection->read_line();

        if (data == "PING") {
            co_await t_connection->write_line("PONG");
            t_connection->close();
            co_return;
        }

        if (connection) {
            co_await t_connection->write_line("Error: Peer already connected");
            t_connection->close();
            co_return;
        }

        connection = std::move(t_connection);

        // Получаем публичный ключ пира
        auto peer_public_key = co_await connection->read_pem_data(data);
        encryption.load_peer_public_key(peer_public_key);
        auto public_key = encryption.get_public_key_bytes();
        
        // Отправляем наш публичный ключ
        co_await connection->write_pem_data(public_key);

        // Получаем AES ключ
        std::string encoded_aes_key = co_await connection->read_line();
        auto encrypted_aes_key = codec::base64_decode(encoded_aes_key);
        auto aes_key = encryption.decrypt_with_private_key(encrypted_aes_key);
        connection->set_aes_key(aes_key);

        // Отправляем никнейм
        co_await send_message({
            {"type", "nickname"},
            {"nickname", nickname}
        });

        // Получаем никнейм пира
        std::string encoded_data = co_await connection->read_line();
        auto encrypted_data = codec::base64_decode(encoded_data);
        auto decrypted_data = encryption.decrypt_with_aes(connection->get_aes_key(), encrypted_data);
        auto message = json::parse(decrypted_data);
        if (message["type"] == "nickname") {
            connection->set_peer_nickname(message["nickname"]);
            std::cout << "Connected to " << connection->get_peer_nickname() << " (" << connection->get_socket().remote_endpoint().address().to_string() << ")" << std::endl;
        } else {
            connection->close();
            connection.reset();
            co_return;
        }

        auto peer_handler = handle_peer();
        asio::co_spawn(io_context, std::move(peer_handler), asio::detached);
    } catch (const std::exception&) {
        if (connection) {
            connection->close();
            connection.reset();
        }
    }
}

asio::awaitable<void> Peer::handle_peer() {
    if (!connection) co_return;
    
    while (true) {
        try {
            std::string encoded_data = co_await connection->read_line();
            auto encrypted_data = codec::base64_decode(encoded_data);
            auto decrypted_data = encryption.decrypt_with_aes(connection->get_aes_key(), encrypted_data);
            auto message = json::parse(decrypted_data);

            if (message["type"] == "disconnect") {
                if (connection) {
                    std::cout << connection->get_peer_nickname() << " disconnected" << std::endl;
                }
                connection->close();
                connection.reset();
                break;
            } else if (message["type"] == "message") {
                std::cout << connection->get_peer_nickname() << ": " << message["content"].get<std::string>() << std::endl;
            }
        } catch (const std::exception&) {
            if (connection) {
                connection->close();
                connection.reset();
            }
            break;
        }
    }
}

asio::awaitable<void> Peer::send_message(const json& message) {
    if (!connection) {
        throw boost::system::system_error(asio::error::not_connected);
    }

    std::string message_str = message.dump();
    auto encrypted_data = encryption.encrypt_with_aes(connection->get_aes_key(), std::vector<unsigned char>(message_str.begin(), message_str.end()));
    std::string encoded_data = codec::base64_encode(encrypted_data);
    
    co_await connection->write_line(encoded_data);
}

asio::awaitable<void> Peer::initiate_disconnect() {
    if (!connection) {
        std::cerr << "No peer connected" << std::endl;
        co_return;
    }

    co_await send_message({
        {"type", "disconnect"}
    });
    
    connection->close();
    connection.reset();
}

std::string Peer::get_nickname() {
    return nickname;
}

asio::awaitable<bool> Peer::check_peer(const std::string& host, unsigned short port) {
    tcp::resolver resolver(io_context);
    tcp::socket socket(io_context);
    
    asio::steady_timer timer(io_context);
    timer.expires_after(std::chrono::milliseconds(100));
    
    // Запускаем таймер
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec) {
            socket.close();
        }
    });

    try {
        auto endpoints = co_await resolver.async_resolve(host, std::to_string(port), asio::use_awaitable);
        co_await asio::async_connect(socket, endpoints, asio::use_awaitable);
        
        // Отправляем пинг-сообщение
        co_await asio::async_write(socket, asio::buffer("PING\n"), asio::use_awaitable);
        
        // Читаем ответ
        asio::streambuf buf;
        auto read_result = co_await asio::async_read_until(socket, buf, '\n', asio::use_awaitable);
        
        timer.cancel();
        
        std::istream is(&buf);
        std::string response;
        std::getline(is, response);
        socket.close();
        
        co_return response == "PONG";
    } catch (const std::exception&) {
        if (socket.is_open()) {
            socket.close();
        }
        timer.cancel();
        co_return false;
    }
}

asio::awaitable<std::vector<std::pair<std::string, int>>> Peer::discover_peers(unsigned short start_port, unsigned short end_port) {
    auto hosts = get_hosts();
    std::vector<std::pair<std::string, int>> peers;
    
    for (const auto& host : hosts) {
        for (int port = start_port; port <= end_port; ++port) {
            if (!(host == network::get_interface_ip() && port == this->port)) {
                if (co_await check_peer(host, port)) {
                    peers.emplace_back(host, port);
                }
            }
        }
    }
    
    co_return peers;
}