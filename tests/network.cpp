#include <network/peer.hpp>
#include <utils/codec.hpp>
#include <utils/endpoint.hpp>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class F> void rejects(F operation, const char* message) {
    try { operation(); } catch (const std::exception&) { return; }
    throw std::runtime_error(message);
}

void test_endpoint_addresses() {
    for (const std::string address : {"localhost:8080", "example.org:65535", "127.0.0.1:1", "[::1]:8080",
                                      "[2001:db8::1]:443"}) {
        const auto endpoint = endpoints::parse(address);
        check(!endpoint.host.empty() && endpoint.port > 0, "Valid endpoint was not parsed");
    }
    check(endpoints::parse("localhost:8080").host == "localhost" &&
          endpoints::parse("localhost:8080").port == 8080, "Hostname endpoint parsed incorrectly");
    check(endpoints::parse("[::1]:8080").host == "::1", "IPv6 brackets retained in hostname");
    check(endpoints::normalize_numeric("[0:0:0:0:0:0:0:1]:08080") == "[::1]:8080",
          "Equivalent numeric endpoints were not normalized");
    for (const std::string address : {"localhost", "example.org", "127.0.0.1", "[::1]", "[2001:db8::1]"}) {
        const auto endpoint = endpoints::parse(address, network::Peer::default_port);
        check(endpoint.port == 42000, "Omitted port did not use the default");
        rejects([&] { endpoints::parse(address); }, "Required port was omitted");
    }
    check(endpoints::parse("[::1]", network::Peer::default_port).host == "::1", "IPv6 host parsed incorrectly");
    check(endpoints::parse("localhost:42001", network::Peer::default_port).port == 42001,
          "Explicit port did not override the default");
    check(endpoints::parse("[::1]:42001", network::Peer::default_port).port == 42001,
          "Explicit IPv6 port did not override the default");
    rejects([&] { endpoints::parse("localhost", 0); }, "Zero default port was accepted");
    for (const std::string address : {"", ":8080", "localhost:", "localhost:0", "localhost:65536",
                                      "localhost:-1", "localhost:+80", "localhost:80x", "localhost:999999999999",
                                      "localhost:80:90", "::1:8080", "[::1]8080", "[::1]:", "[localhost]:80",
                                      "[127.0.0.1]:80", "[::1]:8080x", "[::1:8080", "localhost :80", "localhost:80\n",
                                      "[localhost]", "[]", "::1"}) {
        rejects([&] { endpoints::parse(address); }, "Invalid endpoint accepted");
        rejects([&] { endpoints::parse(address, network::Peer::default_port); }, "Invalid optional port endpoint accepted");
    }
}

void test_frame_buffer_and_limits() {
    asio::io_context io;
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 0));
    tcp::socket sender(io);
    sender.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), acceptor.local_endpoint().port()));
    auto receiver = std::make_shared<network::Connection>(acceptor.accept());
    const std::string data = "first\nsecond\n";
    asio::write(sender, asio::buffer(data));
    auto lines = asio::co_spawn(io, [&]() -> asio::awaitable<void> {
        auto first = co_await receiver->read_line();
        auto second = co_await receiver->read_line();
        check(first == "first" && second == "second", "Coalesced frames were lost");
        bool rejected = false;
        try { co_await receiver->read_pem_data(codec::base64_encode({'b', 'a', 'd'})); }
        catch (const std::exception&) { rejected = true; }
        check(rejected, "Missing PEM markers accepted");
    }, asio::use_future);
    io.run();
    lines.get();
    io.restart();
    const std::string oversized(network::Connection::max_frame_size, 'A');
    asio::write(sender, asio::buffer(oversized));
    auto bounded = asio::co_spawn(io, receiver->read_line(), asio::use_future);
    io.run();
    rejects([&] { bounded.get(); }, "Unterminated oversized frame accepted");
    receiver->close();
}

unsigned short free_port(asio::io_context& io) {
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 0));
    return acceptor.local_endpoint().port();
}

asio::awaitable<std::shared_ptr<network::Connection>> open_client(
    unsigned short port, Encryption& crypto, std::vector<unsigned char> advertised_key,
    std::string server_fingerprint) {
    auto executor = co_await asio::this_coro::executor;
    auto client = std::make_shared<network::Connection>(tcp::socket(executor));
    client->start_deadline(std::chrono::seconds(10));
    co_await client->get_socket().async_connect(
        tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), asio::use_awaitable);
    json hello = {{"port", 34000}, {"public_key", codec::base64_encode(advertised_key)}};
    co_await client->write_line(hello.dump());
    auto response = co_await client->read_line();
    auto encoded_key = json::parse(response).at("public_key").get<std::string>();
    auto server_key = co_await client->read_pem_data(encoded_key);
    crypto.load_peer_public_key(server_key, server_fingerprint);
    co_await client->write_line("READY");
    response = co_await client->read_line();
    check(response == "READY", "Peer did not confirm trust");
    co_return client;
}

asio::awaitable<void> expect_closed(std::shared_ptr<network::Connection> client) {
    bool rejected = false;
    try { co_await client->read_line(); } catch (const std::exception&) { rejected = true; }
    check(rejected && !client->has_timed_out(), "Server did not reject the invalid frame");
    client->close();
}

void test_peer_authentication() {
    asio::io_context io;
    Encryption client_crypto, attacker;
    const auto port = free_port(io);
    network::Peer server("127.0.0.1", port, io, client_crypto.get_public_key_fingerprint());
    server.start();
    std::exception_ptr failure;
    asio::co_spawn(server.get_executor(), [&]() -> asio::awaitable<void> {
        auto client = co_await open_client(port, client_crypto, client_crypto.get_public_key_bytes(),
                                          server.get_public_key_fingerprint());
        auto ciphertext = client_crypto.encrypt_with_peer_public_key({42});
        co_await client->write_line(codec::base64_encode(ciphertext));
        co_await expect_closed(client);
        check(co_await server.check_peer("127.0.0.1", port), "Server stopped after invalid session key");

        // Проверяем подтверждение владения приватным ключом после передачи доверенного открытого ключа.
        client = co_await open_client(port, attacker, client_crypto.get_public_key_bytes(),
                                     server.get_public_key_fingerprint());
        auto secret = attacker.generate_aes_key();
        ciphertext = attacker.encrypt_with_peer_public_key(secret);
        co_await client->write_line(codec::base64_encode(ciphertext));
        auto response = co_await client->read_line();
        rejects([&] { attacker.decrypt_with_private_key(codec::base64_decode(response)); },
                "Impersonator decrypted the responder's challenge");
        co_await client->read_line(); // Зашифрованный никнейм сервера.
        auto wrong_key = Encryption::derive_session_key(secret, attacker.generate_aes_key());
        const std::string forged = R"({"type":"nickname","nickname":"impostor"})";
        ciphertext = attacker.encrypt_with_aes(wrong_key, {forged.begin(), forged.end()});
        co_await client->write_line(codec::base64_encode(ciphertext));
        co_await expect_closed(client);

        // Проверяем рукопожатие, прием нескольких кадров за одну запись и отклонение некорректных кадров.
        for (int kind = 0; kind < 3; ++kind) {
            client = co_await open_client(port, client_crypto, client_crypto.get_public_key_bytes(),
                                         server.get_public_key_fingerprint());
            secret = client_crypto.generate_aes_key();
            ciphertext = client_crypto.encrypt_with_peer_public_key(secret);
            co_await client->write_line(codec::base64_encode(ciphertext));
            response = co_await client->read_line();
            auto responder_secret = client_crypto.decrypt_with_private_key(codec::base64_decode(response));
            auto key = Encryption::derive_session_key(secret, responder_secret);
            response = co_await client->read_line();
            auto greeting = client_crypto.decrypt_with_aes(key, codec::base64_decode(response));
            check(json::parse(greeting).at("type") == "nickname", "Invalid server nickname");
            std::string frames;
            for (const std::string text : {
                    R"({"type":"nickname","nickname":"raw-client","port":34000})",
                    R"({"type":"message","content":"coalesced-first"})",
                    R"({"type":"message","content":"coalesced-second"})"}) {
                ciphertext = client_crypto.encrypt_with_aes(key, {text.begin(), text.end()});
                frames += codec::base64_encode(ciphertext) + "\n";
            }
            if (kind == 0) frames += "\n"; // Пустой зашифрованный кадр.
            if (kind == 1) frames += "AA==\n"; // Усеченный зашифрованный кадр.
            if (kind == 2) {
                ciphertext[12] ^= 1;
                frames += codec::base64_encode(ciphertext) + "\n"; // Некорректный тег GCM.
            }
            co_await asio::async_write(client->get_socket(), asio::buffer(frames), asio::use_awaitable);
            co_await expect_closed(client);
            check(co_await server.check_peer("127.0.0.1", port), "Server stopped after invalid encrypted frame");
        }
    }, [&](std::exception_ptr error) { failure = error; server.close(); });
    std::ostringstream output;
    auto* original_output = std::cout.rdbuf(output.rdbuf());
    io.run();
    std::cout.rdbuf(original_output);
    if (failure) std::rethrow_exception(failure);
    check(output.str().find("raw-client: coalesced-first") != std::string::npos &&
          output.str().find("raw-client: coalesced-second") != std::string::npos,
          "Handshake read-ahead discarded subsequent messages");
    check(output.str().find("Connected to impostor") == std::string::npos, "Impersonator established a chat");
}
}

int main(int argc, char* argv[]) {
    try {
        const std::string suite = argc == 1 ? "all" : argv[1];
        if (argc > 2 || (suite != "all" && suite != "addresses" && suite != "framing" && suite != "handshake"))
            throw std::invalid_argument("Неизвестный набор тестов: " + suite);
        if (suite == "all" || suite == "addresses") test_endpoint_addresses();
        if (suite == "all" || suite == "framing") test_frame_buffer_and_limits();
        if (suite == "all" || suite == "handshake") test_peer_authentication();
        std::cout << "Проверки адресов, кадров и сетевого рукопожатия пройдены\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
