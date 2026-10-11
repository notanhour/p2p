#include <utility>
#include <iostream>
#include <string>
#include <thread>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <network/peer.hpp>
#include <network/discovery.hpp>
#include <utils/endpoint.hpp>
#include <ui/terminal.hpp>
#include <locale>
#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <charconv>
#include <algorithm>

namespace asio = boost::asio;
namespace po = boost::program_options;

namespace {

class Cli {
    network::Peer& peer;
    network::Discovery& discovery;
    ui::Terminal& terminal;
    unsigned short port;
    std::filesystem::path data_directory;
    std::vector<network::DiscoveredPeer> found;

    const network::DiscoveredPeer& selected(const std::string& number) const {
        std::size_t index = 0;
        const auto [end, error] = std::from_chars(number.data(), number.data() + number.size(), index);
        if (error != std::errc{} || end != number.data() + number.size() || index == 0 || index > found.size())
            throw std::invalid_argument("No peer with this number. Run 'discover' to list peers.");
        return found[index - 1];
    }

    static std::string address(const std::string& host, unsigned short port) {
        return (host.find(':') == std::string::npos ? host : "[" + host + "]") + ":" + std::to_string(port);
    }

public:
    Cli(network::Peer& peer, network::Discovery& discovery, ui::Terminal& terminal,
        unsigned short port, std::filesystem::path directory)
        : peer(peer), discovery(discovery), terminal(terminal), port(port), data_directory(std::move(directory)) {}

    asio::awaitable<void> process(std::string line) {
        std::istringstream input(line);
        std::string command;
        input >> command;
        if (command.empty()) co_return;
        try {
            if (command == "connect") {
                std::string target, extra;
                if (!(input >> target) || (input >> extra)) {
                    terminal.write("Usage: connect <host[:port]> or connect <number> (default port: " + std::to_string(network::Peer::default_port) + ")", ui::Style::warning);
                    co_return;
                }
                endpoints::Endpoint endpoint;
                if (std::all_of(target.begin(), target.end(), [](unsigned char ch) { return ch >= '0' && ch <= '9'; })) {
                    const auto& entry = selected(target);
                    endpoint = {entry.addresses.front(), entry.port};
                } else endpoint = endpoints::parse(target, network::Peer::default_port);
                if (endpoint.host == "localhost") endpoint.host = "127.0.0.1";
                const auto error = co_await peer.connect_to_peer(endpoint.host, endpoint.port);
                if (error == asio::error::already_connected) terminal.write("Already connected to a peer.", ui::Style::warning);
                else if (error && error != asio::error::operation_aborted && error != asio::error::timed_out)
                    terminal.write("Connection failed: " + error.message(), ui::Style::error);
            } else if (command == "yes" || command == "no") {
                peer.confirm_peer(command == "yes");
                if (command == "yes") terminal.write("Peer trust confirmed.", ui::Style::success);
            } else if (command == "trust") {
                std::string target, fingerprint, extra;
                if (!(input >> target >> fingerprint) || (input >> extra)) {
                    terminal.write("Usage: trust <address[:port]> <fingerprint> (default port: " + std::to_string(network::Peer::default_port) + ")", ui::Style::warning);
                    co_return;
                }
                auto endpoint = endpoints::parse(target, network::Peer::default_port);
                if (endpoint.host == "localhost") endpoint.host = "127.0.0.1";
                peer.trust_peer(endpoint.host, endpoint.port, fingerprint);
                terminal.write("Trusted peer fingerprint updated.", ui::Style::success);
            } else if (command == "disconnect") {
                co_await peer.initiate_disconnect();
            } else if (command == "send") {
                const auto begin = line.find_first_not_of(" \t\r\n");
                std::string message = line.substr(begin + command.size());
                if (!message.empty() && (message.front() == ' ' || message.front() == '\t')) message.erase(0, 1);
                if (message.empty()) {
                    terminal.echo_command(line);
                    terminal.write("Usage: send <message>", ui::Style::warning);
                    co_return;
                }
                try {
                    co_await peer.send_message({{"type", "message"}, {"content", message}});
                    terminal.write("You: " + message, ui::Style::outgoing);
                } catch (const boost::system::system_error& error) {
                    terminal.echo_command(line);
                    if (error.code() == asio::error::not_connected) terminal.write("No peer connected.", ui::Style::warning);
                    else terminal.write("Failed to send message: " + error.code().message(), ui::Style::error);
                } catch (const std::exception& error) {
                    terminal.echo_command(line);
                    terminal.write("Failed to send message: " + std::string(error.what()), ui::Style::error);
                }
            } else if (command == "discover") {
                std::string number, extra;
                if (input >> number) {
                    if (input >> extra) {
                        terminal.write("Usage: discover or discover <number>", ui::Style::warning);
                        co_return;
                    }
                    const auto& entry = selected(number);
                    std::string output = "Addresses for peer [" + number + "]:";
                    for (const auto& host : entry.addresses) output += "\n" + address(host, entry.port);
                    terminal.write(output, ui::Style::listing);
                    co_return;
                }
                terminal.write("Discovering peers...", ui::Style::muted);
                try {
                    auto peers = co_await discovery.discover();
                    found = std::move(peers);
                    if (found.empty()) terminal.write("No active peers found.", ui::Style::muted);
                    else {
                        std::string output = "Found " + std::to_string(found.size()) + (found.size() == 1 ? " peer:" : " peers:");
                        for (std::size_t i = 0; i < found.size(); ++i) {
                            const auto& entry = found[i];
                            output += "\n[" + std::to_string(i + 1) + "] " + address(entry.addresses.front(), entry.port);
                            const auto additional = entry.addresses.size() - 1;
                            if (additional) output += " (+" + std::to_string(additional) + (additional == 1 ? " address)" : " addresses)");
                        }
                        terminal.write(output, ui::Style::listing);
                    }
                } catch (const std::exception& error) {
                    terminal.write("Failed to discover: " + std::string(error.what()), ui::Style::error);
                }
            } else if (command == "info") {
                terminal.write("Name: " + peer.get_nickname() + "\nPort: " + std::to_string(port) +
                               "\nProfile: " + data_directory.string() + "\nSHA-256: " + peer.get_public_key_fingerprint() +
                               "\nNew peers require confirmation. Known peers are verified against saved keys.", ui::Style::details);
            } else if (command == "help") {
                terminal.write(
                    "Available commands:\n"
                    "connect <host[:port]> / connect <number> — Connect to a peer (default port: " + std::to_string(network::Peer::default_port) + ")\n"
                    "yes / no — Confirm or decline a new peer\n"
                    "trust <address[:port]> <fingerprint> — Set a trusted peer key (default port: " + std::to_string(network::Peer::default_port) + ")\n"
                    "disconnect — Break the connection\n"
                    "discover / discover <number> — Discover peers or show all addresses of a peer\n"
                    "send <message> — Send a message\n"
                    "Enter — Submit, Alt+Enter / Ctrl+J — New line in a message\n"
                    "info — Show your name, port, profile and fingerprint\n"
                    "help — Show this help\n"
                    "quit — Exit", ui::Style::details);
            } else terminal.write("Unknown command. Type 'help' for available commands.", ui::Style::warning);
        } catch (const boost::system::system_error& error) {
            terminal.write("Error: " + error.code().message(), ui::Style::error);
        } catch (const std::exception& error) {
            terminal.write("Error: " + std::string(error.what()), ui::Style::error);
        }
    }
};

}

int main(int argc, char* argv[]) {
    try {
        // Выбираем локаль окружения с запасным вариантом для минимальных систем.
        try { std::locale::global(std::locale("")); }
        catch (const std::runtime_error&) { std::locale::global(std::locale::classic()); }

        po::options_description description("Allowed options");
        description.add_options()
            ("help,h", "Show help message")
            ("port,p", po::value<unsigned short>()->default_value(network::Peer::default_port), "Port to bind")
            ("peer-fingerprint", po::value<std::string>()->default_value(""), "Expected peer SHA-256 fingerprint")
            ("data-dir", po::value<std::string>(), "Directory for identity and trusted peers");
        po::variables_map variables;
        po::store(po::parse_command_line(argc, argv, description), variables);
        if (variables.count("help")) { std::cout << description << std::endl; return 0; }
        po::notify(variables);
        const auto port = variables["port"].as<unsigned short>();
        if (port == 0) throw std::invalid_argument("Port must be greater than zero");
        std::filesystem::path data_directory;
        if (variables.count("data-dir")) {
            data_directory = variables["data-dir"].as<std::string>();
            if (data_directory.empty()) throw std::invalid_argument("Data directory must not be empty");
        } else if (const char* home = std::getenv("HOME"); home && *home) {
            data_directory = std::filesystem::path(home) / ".config" / "p2p";
        } else throw std::runtime_error("Set --data-dir when HOME is unavailable");

        ui::Terminal terminal;
        asio::io_context io_context;
        auto work_guard = asio::make_work_guard(io_context);
        network::Peer peer("0.0.0.0", port, io_context,
                           variables["peer-fingerprint"].as<std::string>(), data_directory);
        network::Discovery discovery(peer.get_executor(),
            "p2p-" + peer.get_public_key_fingerprint().substr(0, 16) + "-" + std::to_string(port), port);
        Cli cli(peer, discovery, terminal, port, data_directory);
        peer.set_output_handler([&](const std::string& text, network::OutputKind kind) {
            auto style = ui::Style::normal;
            switch (kind) {
                case network::OutputKind::success: style = ui::Style::success; break;
                case network::OutputKind::warning: style = ui::Style::warning; break;
                case network::OutputKind::error: style = ui::Style::error; break;
                case network::OutputKind::message: style = ui::Style::incoming; break;
                case network::OutputKind::info: break;
            }
            terminal.write(text, style);
        });
        peer.set_trust_request_handler(
            [&](const std::string& endpoint, const std::string& fingerprint) { terminal.request_trust(endpoint, fingerprint); },
            [&] { terminal.finish_trust(); });
        terminal.write("p2p · " + peer.get_nickname(), ui::Style::heading);
        terminal.write("Type 'help' for commands.", ui::Style::muted);
        discovery.start();
        peer.start();
        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code& error, int) {
            if (!error) terminal.stop();
        });
        std::thread io_thread([&] { io_context.run(); });
        try {
            while (auto line = terminal.read_line()) {
                if (*line == "quit") break;
                std::istringstream input(*line);
                std::string command;
                input >> command;
                // Подключение и поиск выполняются в фоне, чтобы CLI продолжал принимать команды.
                if (command == "connect" || command == "discover") {
                    asio::co_spawn(peer.get_executor(), cli.process(std::move(*line)), asio::detached);
                } else {
                    asio::co_spawn(peer.get_executor(), cli.process(std::move(*line)), asio::use_future).get();
                }
            }
        } catch (...) {
            discovery.stop();
            peer.close();
            io_thread.join();
            throw;
        }
        discovery.stop();
        peer.close();
        io_thread.join();
    } catch (const boost::system::system_error& error) {
        std::cerr << "Error: " << error.code().message() << std::endl;
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << std::endl;
        return 1;
    }
    return 0;
}
