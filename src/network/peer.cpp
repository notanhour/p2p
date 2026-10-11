#include <network/peer.hpp>
#include <utils/codec.hpp>
#include <utils/namegen.hpp>
#include <openssl/crypto.h>
#include <exception>
#include <iostream>
#include <sstream>
#include <stdexcept>

using namespace network;

namespace {
class TrustDeclined final : public std::exception {};

std::string connection_error(const std::exception& error) {
    if (const auto* system_error = dynamic_cast<const boost::system::system_error*>(&error)) {
        const auto code = system_error->code();
        if (code == asio::error::eof || code == asio::error::connection_reset)
            return "Peer closed the connection";
        return code.message();
    }
    return error.what();
}
}

Connection::Connection(tcp::socket socket)
    : socket(std::move(socket)), resolver(this->socket.get_executor()),
      deadline(this->socket.get_executor()), resolve_ready(this->socket.get_executor()),
      confirmation_ready(this->socket.get_executor()), receive_buffer(max_frame_size) {}

Connection::~Connection() { close(); }

tcp::socket& Connection::get_socket() { return socket; }
const std::vector<unsigned char>& Connection::get_aes_key() const { return aes_key; }
const std::string& Connection::get_peer_nickname() const { return peer_nickname; }
void Connection::set_peer_nickname(const std::string& nickname) { peer_nickname = nickname; }
bool Connection::is_ready() const { return ready && !closed; }
void Connection::mark_ready() { ensure_open(); ready = true; }
bool Connection::has_timed_out() const { return timed_out; }

void Connection::set_peer_identity(const std::string& endpoint, const std::string& fingerprint, unsigned short port) {
    peer_endpoint = endpoint;
    peer_fingerprint = fingerprint;
    peer_port = port;
}

const std::string& Connection::get_peer_endpoint() const { return peer_endpoint; }
const std::string& Connection::get_peer_fingerprint() const { return peer_fingerprint; }
unsigned short Connection::get_peer_port() const { return peer_port; }

void Connection::prepare_confirmation() {
    ensure_open();
    trust_decision.reset();
    confirmation_ready.expires_at(std::chrono::steady_clock::time_point::max());
}

void Connection::confirm(bool trusted) {
    ensure_open();
    trust_decision = trusted;
    confirmation_ready.cancel();
}

asio::awaitable<bool> Connection::wait_for_confirmation() {
    ensure_open();
    if (!trust_decision) {
        boost::system::error_code ec;
        co_await confirmation_ready.async_wait(asio::redirect_error(asio::use_awaitable, ec));
    }
    ensure_open();
    if (!trust_decision) throw std::runtime_error("No trust decision available");
    co_return *trust_decision;
}

asio::awaitable<tcp::resolver::results_type> Connection::resolve(std::string host, unsigned short port) {
    ensure_open();
    resolve_ready.expires_at(std::chrono::steady_clock::time_point::max());
    std::weak_ptr<Connection> weak = shared_from_this();
    resolver.async_resolve(host, std::to_string(port),
        [weak](const boost::system::error_code& ec, tcp::resolver::results_type endpoints) {
            if (auto session = weak.lock(); session && !session->closed) {
                session->resolve_error = ec;
                session->resolved_endpoints = std::move(endpoints);
                session->resolve_ready.cancel();
            }
        });
    // Системное разрешение DNS может завершиться после resolver.cancel(). Отдельный
    // сигнал позволяет немедленно завершить ожидание по тайм-ауту и игнорировать поздний результат.
    boost::system::error_code ec;
    co_await resolve_ready.async_wait(asio::redirect_error(asio::use_awaitable, ec));
    ensure_open();
    if (resolve_error) throw boost::system::system_error(resolve_error);
    co_return std::move(resolved_endpoints);
}

void Connection::ensure_open() const {
    if (closed) throw boost::system::system_error(asio::error::operation_aborted);
}

void Connection::set_aes_key(const std::vector<unsigned char>& key) {
    if (key.size() != 32) throw std::runtime_error("Session key must contain exactly 32 bytes");
    ensure_open();
    OPENSSL_cleanse(aes_key.data(), aes_key.size());
    aes_key = key;
}

void Connection::start_deadline(std::chrono::steady_clock::duration timeout) {
    ensure_open();
    const auto generation = ++deadline_generation;
    deadline.expires_after(timeout);
    std::weak_ptr<Connection> weak = shared_from_this();
    deadline.async_wait([weak, generation](const boost::system::error_code& ec) {
        if (auto session = weak.lock(); !ec && session && generation == session->deadline_generation) {
            session->timed_out = true;
            session->close();
        }
    });
}

void Connection::stop_deadline() {
    ++deadline_generation;
    deadline.cancel();
}

void Connection::close() {
    if (closed) return;
    closed = true;
    ready = false;
    stop_deadline();
    resolver.cancel();
    resolve_ready.cancel();
    confirmation_ready.cancel();
    boost::system::error_code ec;
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.close(ec);
    OPENSSL_cleanse(aes_key.data(), aes_key.size());
    aes_key.clear();
}

asio::awaitable<std::string> Connection::read_line() {
    ensure_open();
    // read_until может прочитать данные следующих кадров. getline извлекает из общего буфера одну строку.
    co_await asio::async_read_until(socket, receive_buffer, '\n', asio::use_awaitable);
    ensure_open();
    std::istream input(&receive_buffer);
    std::string line;
    std::getline(input, line);
    co_return line;
}

asio::awaitable<void> Connection::write_line(std::string line) {
    ensure_open();
    if (line.size() >= max_frame_size || line.find('\n') != std::string::npos)
        throw std::length_error("Invalid or oversized network frame");
    if (writing) throw boost::system::system_error(asio::error::already_started);
    line += '\n';
    writing = true;
    try {
        // Строка принадлежит корутине до завершения асинхронной записи.
        co_await asio::async_write(socket, asio::buffer(line), asio::use_awaitable);
        writing = false;
        ensure_open();
    } catch (...) {
        writing = false;
        throw;
    }
}

asio::awaitable<std::vector<unsigned char>> Connection::read_pem_data(const std::string& encoded) {
    auto decoded = codec::base64_decode(encoded);
    std::string pem(decoded.begin(), decoded.end());
    if (!pem.starts_with("-----BEGIN PUBLIC KEY-----\n") ||
        pem.find("-----END PUBLIC KEY-----") == std::string::npos)
        throw std::runtime_error("Invalid PEM public key");
    co_return decoded;
}

asio::awaitable<void> Connection::write_pem_data(const std::vector<unsigned char>& data) {
    co_await write_line(codec::base64_encode(data));
}

Peer::Peer(const std::string& host, unsigned short port, asio::io_context& io_context,
           const std::string& trusted_fingerprint, const std::filesystem::path& data_directory)
    : host(host), port(port), io_context(io_context), executor(asio::make_strand(io_context)),
      acceptor(executor, tcp::endpoint(asio::ip::make_address(host), port)),
      encryption(data_directory.empty() ? std::filesystem::path{} : data_directory / "identity.pem"),
      known_peers(data_directory), nickname(namegen::generate()),
      public_key_fingerprint(encryption.get_public_key_fingerprint()) {
    if (!trusted_fingerprint.empty()) initial_fingerprint = storage::normalize_fingerprint(trusted_fingerprint);
}

asio::strand<asio::io_context::executor_type> Peer::get_executor() const { return executor; }
std::string Peer::get_nickname() const { return nickname; }
std::string Peer::get_public_key_fingerprint() const { return public_key_fingerprint; }

void Peer::set_trust_request_handler(std::function<void(const std::string&, const std::string&)> handler,
                                    std::function<void()> end_handler) {
    trust_request_handler = std::move(handler);
    trust_end_handler = std::move(end_handler);
}

void Peer::set_output_handler(std::function<void(const std::string&, OutputKind)> handler) {
    output_handler = std::move(handler);
}

void Peer::output(const std::string& text, OutputKind kind) {
    if (output_handler) output_handler(text, kind);
    else std::cout << text << std::endl;
}

void Peer::confirm_peer(bool trusted) {
    if (!pending_confirmation) throw std::runtime_error("No peer is awaiting confirmation");
    pending_confirmation->confirm(trusted);
    pending_confirmation.reset();
    if (trust_end_handler) trust_end_handler();
}

void Peer::trust_peer(const std::string& host, unsigned short port, const std::string& fingerprint) {
    if (connection) throw std::runtime_error("Disconnect before changing the trusted peer");
    if (port == 0) throw std::invalid_argument("Peer port must be greater than zero");
    std::ostringstream endpoint;
    endpoint << tcp::endpoint(asio::ip::make_address(host), port);
    known_peers.remember(endpoint.str(), fingerprint, true);
}

void Peer::start() {
    asio::co_spawn(executor, accept_connections(), asio::detached);
}

void Peer::close() {
    if (closed.exchange(true)) return;
    asio::post(executor, [this] {
        boost::system::error_code ec;
        acceptor.close(ec);
        for (const auto& session : active_connections) session->close();
        active_connections.clear();
        connection.reset();
        pending_confirmation.reset();
        io_context.stop();
    });
}

void Peer::release_connection(const std::shared_ptr<Connection>& session) {
    session->close();
    active_connections.erase(session);
    if (connection == session) connection.reset();
    if (pending_confirmation == session) {
        pending_confirmation.reset();
        if (trust_end_handler) trust_end_handler();
    }
}

asio::awaitable<void> Peer::accept_connections() {
    while (!closed.load()) {
        try {
            auto socket = co_await acceptor.async_accept(asio::use_awaitable);
            // Ограничиваем суммарное потребление памяти и число таймеров для незавершенных рукопожатий.
            if (closed.load() || active_connections.size() >= 32) {
                boost::system::error_code ec;
                socket.close(ec);
                continue;
            }
            auto session = std::make_shared<Connection>(std::move(socket));
            active_connections.insert(session);
            session->start_deadline(handshake_timeout);
            asio::co_spawn(executor, handle_new_connection(session), asio::detached);
        } catch (const std::exception&) {
            break;
        }
    }
}

asio::awaitable<void> Peer::send_on(std::shared_ptr<Connection> session, json message) {
    const auto text = message.dump();
    const auto ciphertext = encryption.encrypt_with_aes(session->get_aes_key(),
                                                       std::vector<unsigned char>(text.begin(), text.end()));
    co_await session->write_line(codec::base64_encode(ciphertext));
}

asio::awaitable<void> Peer::send_public_key(std::shared_ptr<Connection> session) {
    json hello = {{"port", port}, {"public_key", codec::base64_encode(encryption.get_public_key_bytes())}};
    co_await session->write_line(hello.dump());
}

asio::awaitable<std::vector<unsigned char>> Peer::read_public_key(
    std::shared_ptr<Connection> session, std::string frame, std::optional<unsigned short> target_port) {
    const auto hello = json::parse(frame);
    if (!hello.at("port").is_number_integer()) throw std::runtime_error("Invalid peer port");
    const auto advertised_port = hello.at("port").get<std::uint64_t>();
    if (advertised_port == 0 || advertised_port > 65535) throw std::runtime_error("Invalid peer port");
    const auto encoded_key = hello.at("public_key").get<std::string>();
    auto public_key = co_await session->read_pem_data(encoded_key);
    std::ostringstream endpoint;
    endpoint << tcp::endpoint(session->get_socket().remote_endpoint().address(),
                             target_port.value_or(static_cast<unsigned short>(advertised_port)));
    session->set_peer_identity(endpoint.str(), Encryption::public_key_fingerprint(public_key),
                               static_cast<unsigned short>(advertised_port));
    co_return public_key;
}

asio::awaitable<void> Peer::authenticate_peer(std::shared_ptr<Connection> session,
                                           std::vector<unsigned char> public_key) {
    // Оба участника выделяют время на подтверждение независимо от наличия сохраненного ключа собеседника.
    session->start_deadline(trust_timeout);
    const auto& endpoint = session->get_peer_endpoint();
    const auto& fingerprint = session->get_peer_fingerprint();
    const auto saved = known_peers.find(endpoint);
    if (saved && *saved != fingerprint)
        throw std::runtime_error("Peer key changed for " + endpoint + ". Stored SHA-256: " + *saved +
                                 ". Received SHA-256: " + fingerprint +
                                 ". Verify the new key and update it explicitly with trust <address[:port]> <fingerprint>");
    if (!initial_fingerprint.empty() && initial_fingerprint != fingerprint)
        throw std::runtime_error("Peer fingerprint does not match --peer-fingerprint");
    if (!saved && initial_fingerprint.empty()) {
        if (!trust_request_handler) throw std::runtime_error("Unknown peer requires confirmation");
        session->prepare_confirmation();
        pending_confirmation = session;
        trust_request_handler(endpoint, fingerprint);
        const bool trusted = co_await session->wait_for_confirmation();
        if (pending_confirmation == session) pending_confirmation.reset();
        if (!trusted) {
            try {
                co_await session->write_line("DECLINED");
            } catch (const boost::system::system_error&) {
                // Локальный отказ остается в силе, даже если собеседник закрыл соединение.
            }
            throw TrustDeclined{};
        }
    }
    encryption.load_peer_public_key(public_key, fingerprint);
    co_await session->write_line("READY");
    const auto response = co_await session->read_line();
    if (response == "DECLINED") throw std::runtime_error("Peer declined the connection");
    if (response != "READY") throw std::runtime_error("Expected peer trust confirmation");
    session->start_deadline(handshake_timeout);
}

asio::awaitable<void> Peer::exchange_nicknames(std::shared_ptr<Connection> session) {
    json greeting = {{"type", "nickname"}, {"nickname", nickname}, {"port", port}};
    co_await send_on(session, std::move(greeting));
    auto encoded = co_await session->read_line();
    auto plaintext = encryption.decrypt_with_aes(session->get_aes_key(), codec::base64_decode(encoded));
    const auto message = json::parse(plaintext);
    if (message.at("type") != "nickname" || !message.at("nickname").is_string())
        throw std::runtime_error("Expected an authenticated nickname");
    if (message.at("port") != session->get_peer_port())
        throw std::runtime_error("Peer listening port does not match the authenticated greeting");
    session->set_peer_nickname(message.at("nickname").get<std::string>());
    // Сохраняем доверие после зашифрованного подтверждения владения приватным ключом.
    known_peers.remember(session->get_peer_endpoint(), session->get_peer_fingerprint());
    session->mark_ready();
    session->stop_deadline();
    output("\nConnected to " + session->get_peer_nickname() + " · " + session->get_peer_endpoint(), OutputKind::success);
}

asio::awaitable<boost::system::error_code> Peer::connect_to_peer(const std::string& peer_host, unsigned short peer_port) {
    if (closed.load()) co_return asio::error::operation_aborted;
    if (connection) co_return asio::error::already_connected;
    if (peer_host == host && peer_port == port) {
        output("Connection failed: Cannot connect to this peer", OutputKind::error);
        co_return asio::error::operation_aborted;
    }

    auto session = std::make_shared<Connection>(tcp::socket(executor));
    // Резервируем соединение до разрешения DNS и первой приостановки корутины.
    connection = session;
    active_connections.insert(session);
    session->start_deadline(handshake_timeout);
    try {
        auto endpoints = co_await session->resolve(peer_host, peer_port);
        session->ensure_open();
        co_await asio::async_connect(session->get_socket(), endpoints, asio::use_awaitable);
        session->ensure_open();
        co_await send_public_key(session);
        auto response = co_await session->read_line();
        if (response == "Error: Peer already connected") {
            release_connection(session);
            co_return asio::error::already_connected;
        }
        auto peer_public_key = co_await read_public_key(session, std::move(response), peer_port);
        co_await authenticate_peer(session, std::move(peer_public_key));

        // Каждая сторона передает случайный секрет, зашифрованный доверенным RSA-ключом собеседника.
        // Владение итоговым ключом подтверждает владение обоими соответствующими приватными ключами.
        auto initiator_secret = encryption.generate_aes_key();
        auto encrypted_secret = encryption.encrypt_with_peer_public_key(initiator_secret);
        co_await session->write_line(codec::base64_encode(encrypted_secret));
        auto encoded_secret = co_await session->read_line();
        auto responder_secret = encryption.decrypt_with_private_key(codec::base64_decode(encoded_secret));
        session->set_aes_key(Encryption::derive_session_key(initiator_secret, responder_secret));
        co_await exchange_nicknames(session);
        asio::co_spawn(executor, handle_peer(session), asio::detached);
        co_return boost::system::error_code{};
    } catch (const TrustDeclined&) {
        release_connection(session);
        output("Peer trust declined.", OutputKind::warning);
        co_return asio::error::operation_aborted;
    } catch (const std::exception& e) {
        const bool timeout = session->has_timed_out();
        release_connection(session);
        output("Connection failed: " + (timeout ? std::string("handshake timed out") : connection_error(e)), OutputKind::error);
        co_return timeout ? asio::error::timed_out : asio::error::operation_aborted;
    }
}

asio::awaitable<void> Peer::handle_new_connection(std::shared_ptr<Connection> session) {
    try {
        auto data = co_await session->read_line();
        if (data == "PING") {
            co_await session->write_line("PONG");
            release_connection(session);
            co_return;
        }
        if (connection) {
            co_await session->write_line("Error: Peer already connected");
            release_connection(session);
            co_return;
        }
        auto peer_public_key = co_await read_public_key(session, std::move(data));
        connection = session;
        co_await send_public_key(session);
        co_await authenticate_peer(session, std::move(peer_public_key));
        auto encoded_secret = co_await session->read_line();
        auto initiator_secret = encryption.decrypt_with_private_key(codec::base64_decode(encoded_secret));
        if (initiator_secret.size() != 32) throw std::runtime_error("Session secret must contain exactly 32 bytes");
        auto responder_secret = encryption.generate_aes_key();
        auto encrypted_secret = encryption.encrypt_with_peer_public_key(responder_secret);
        session->set_aes_key(Encryption::derive_session_key(initiator_secret, responder_secret));
        co_await session->write_line(codec::base64_encode(encrypted_secret));
        co_await exchange_nicknames(session);
        asio::co_spawn(executor, handle_peer(session), asio::detached);
    } catch (const TrustDeclined&) {
        release_connection(session);
        output("Peer trust declined.", OutputKind::warning);
    } catch (const std::exception& e) {
        if (connection == session)
            output("Incoming connection failed: " +
                   (session->has_timed_out() ? std::string("handshake timed out") : connection_error(e)), OutputKind::error);
        release_connection(session);
    }
}

asio::awaitable<void> Peer::handle_peer(std::shared_ptr<Connection> session) {
    bool disconnected = false;
    try {
        while (session->is_ready()) {
            auto encoded = co_await session->read_line();
            auto plaintext = encryption.decrypt_with_aes(session->get_aes_key(), codec::base64_decode(encoded));
            const auto message = json::parse(plaintext);
            if (message.at("type") == "disconnect") {
                disconnected = true;
                break;
            }
            if (message.at("type") == "message")
                output(session->get_peer_nickname() + ": " + message.at("content").get<std::string>(), OutputKind::message);
        }
    } catch (const std::exception&) {
        // Корутина сохраняет свою сессию независимо от состояния текущего соединения.
    }
    if (!closed.load() && (disconnected || connection == session))
        output(session->get_peer_nickname() + " disconnected", OutputKind::warning);
    release_connection(session);
}

asio::awaitable<void> Peer::send_message(const json& message) {
    auto session = connection;
    if (!session || !session->is_ready()) throw boost::system::system_error(asio::error::not_connected);
    co_await send_on(session, message);
}

asio::awaitable<void> Peer::initiate_disconnect() {
    auto session = connection;
    if (!session) {
        output("No peer connected.", OutputKind::warning);
        co_return;
    }
    try {
        if (session->is_ready()) {
            session->start_deadline(std::chrono::seconds(2));
            json message = {{"type", "disconnect"}};
            co_await send_on(session, std::move(message));
        }
    } catch (const std::exception&) {
        // Очищаем сессию и при ошибке отправки уведомления.
    }
    const auto name = session->get_peer_nickname();
    release_connection(session);
    output(name.empty() ? "Connection cancelled." : "Disconnected from " + name, OutputKind::warning);
}

asio::awaitable<bool> Peer::check_peer(const std::string& host, unsigned short port) {
    if (closed.load()) co_return false;
    auto session = std::make_shared<Connection>(tcp::socket(executor));
    active_connections.insert(session);
    session->start_deadline(std::chrono::milliseconds(100));
    try {
        auto endpoints = co_await session->resolve(host, port);
        session->ensure_open();
        co_await asio::async_connect(session->get_socket(), endpoints, asio::use_awaitable);
        session->ensure_open();
        co_await session->write_line("PING");
        auto response = co_await session->read_line();
        release_connection(session);
        co_return response == "PONG";
    } catch (const std::exception&) {
        release_connection(session);
        co_return false;
    }
}
