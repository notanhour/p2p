#pragma once

#include <utility>
#include <boost/asio.hpp>
#include <memory>
#include <string>
#include <vector>

namespace network {

struct DiscoveredPeer {
    std::string service;
    unsigned short port;
    std::vector<std::string> addresses;
};

class Discovery {
private:
    struct Impl;
    std::shared_ptr<Impl> impl;

public:
    Discovery(boost::asio::any_io_executor executor, std::string instance, unsigned short port);
    ~Discovery();
    Discovery(const Discovery&) = delete;
    Discovery& operator=(const Discovery&) = delete;
    void start();
    // Можно вызывать из любого потока. Остановка пробуждает цикл Avahi.
    void stop();
    // Запускайте корутину на переданном исполнителе, последовательно с другими вызовами discover.
    boost::asio::awaitable<std::vector<DiscoveredPeer>> discover();
};

}
