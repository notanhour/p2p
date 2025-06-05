#include <iostream>
#include <string>
#include <thread>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <network/peer.hpp>
#include <unistd.h>
#include <locale>

namespace asio = boost::asio;
namespace po = boost::program_options;

asio::awaitable<void> process_cli(network::Peer& peer, const std::string line) {
    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;

    try {
        if (cmd == "connect") {
            std::string host;
            unsigned short port;
            if (iss >> host >> port) {
                if (host == "localhost" || host == "127.0.0.1") host = "0.0.0.0";
                try {
                    auto ec = co_await peer.connect_to_peer(host, port);
                    if (ec) {
                        if (ec == asio::error::already_connected) {
                            std::cerr << "Already connected to a peer." << std::endl;
                        } else if (ec == asio::error::operation_aborted) {
                            std::cerr << "Connection failed." << std::endl;
                        }
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Failed to connect: " << e.what() << std::endl;
                }
            } else {
                std::cout << "Usage: connect <host> <port>" << std::endl;
            }
        } else if (cmd == "disconnect") {
            co_await peer.initiate_disconnect();
        } else if (cmd == "send") {
            std::string msg;
            std::getline(iss, msg);
            if (msg.size() > 0 && msg.front() == ' ') msg.erase(0, 1);
            try {
                co_await peer.send_message({
                    {"type", "message"},
                    {"content", msg}
                });
            } catch (const std::exception& e) {
                if (std::string(e.what()).find("Transport endpoint is not connected") != std::string::npos) {
                    std::cerr << "No peer connected." << std::endl;
                } else {
                    std::cerr << "Failed to send message: " << e.what() << std::endl;
                }
            }
        } else if (cmd == "scan") {
            std::cout << "Scanning network..." << std::endl;
            int start_port = 8080, end_port = 8100;
            try {
                auto found = co_await peer.discover_peers(start_port, end_port);
                if (found.size() > 0) {
                    std::cout << "Found active peers: " << std::endl;
                    for (auto& [addr, port] : found) {
                        std::cout << " > " << addr << ":" << port << std::endl;
                    }
                } else {
                    std::cout << "No active peers found." << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "Failed to scan: " << e.what() << std::endl;
            }
        } else if (cmd == "help") {
            std::cout
                << "Available commands:" << std::endl
                << "connect <host> <port> — Connect to a peer" << std::endl
                << "disconnect — Break the connection" << std::endl
                << "scan — Scan for active peers" << std::endl
                << "send <message> — Send a message" << std::endl
                << "help — Show this help" << std::endl;
        } else {
            std::cout << "Unknown command. Type 'help' for available commands." << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    try {
        // Локализация и кодировка
        std::locale::global(std::locale("en_US.UTF-8"));

        // Разбираем аргументы командной строки
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help,h", "Show help message")
            ("port,p", po::value<unsigned short>()->required(), "Port to bind");

            po::variables_map variables;
            po::store(po::parse_command_line(argc, argv, desc), variables);

            if (variables.count("help")) {
                std::cout << desc << std::endl;
                return 0;
            }
            po::notify(variables);

            unsigned short port = variables["port"].as<unsigned short>();

            asio::io_context io_context;
            auto work_guard = asio::make_work_guard(io_context);
            
            network::Peer peer("0.0.0.0", port, io_context);
            peer.start();

            asio::signal_set signals(io_context, SIGINT, SIGTERM);
            signals.async_wait([&](const boost::system::error_code&, int) {
                peer.close();
                close(0); // Закрываем стандартный ввод
                std::exit(0);
            });
            
            std::thread io_thread([&io_context]() {
                io_context.run();
            });

            std::cout << "P2P chat started. Type 'quit' to exit." << std::endl;
            std::cout << "Your name is " << peer.get_nickname() << std::endl;

            std::string line;
            while (true) {
                if (!std::getline(std::cin, line) || line == "quit") {
                    peer.close();
                    break;
                }
                std::future<void> future = asio::co_spawn(io_context, process_cli(peer, line), asio::use_future);
                future.get();
            }

            if (io_thread.joinable()) {
                io_thread.join();
            }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}