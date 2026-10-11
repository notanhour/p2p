#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <algorithm>
#include <charconv>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace endpoints {

struct Endpoint {
    std::string host;
    unsigned short port;
};

inline Endpoint parse(std::string_view value, std::optional<unsigned short> fallback_port = {}) {
    const auto invalid = [&] {
        return std::invalid_argument(fallback_port
            ? "Expected host or host:port (IPv6 in brackets), with port 1-65535"
            : "Expected host:port or [IPv6]:port with port 1-65535");
    };
    if (value.empty() || std::any_of(value.begin(), value.end(), [](unsigned char ch) { return ch <= 32 || ch == 127; }))
        throw invalid();
    std::string_view host, port_text;
    bool explicit_port = false;
    if (value.front() == '[') {
        const auto end = value.find(']');
        if (end == std::string_view::npos) throw invalid();
        host = value.substr(1, end - 1);
        if (end + 1 < value.size()) {
            if (value[end + 1] != ':') throw invalid();
            port_text = value.substr(end + 2);
            explicit_port = true;
        }
        boost::system::error_code error;
        boost::asio::ip::make_address_v6(std::string(host), error);
        if (error) throw invalid();
    } else {
        const auto separator = value.find(':');
        if (value.find_first_of("[]") != std::string_view::npos) throw invalid();
        if (separator == std::string_view::npos) {
            host = value;
        } else {
            if (value.find(':', separator + 1) != std::string_view::npos) throw invalid();
            host = value.substr(0, separator);
            port_text = value.substr(separator + 1);
            explicit_port = true;
        }
    }
    if (host.empty()) throw invalid();
    if (!explicit_port) {
        if (!fallback_port || *fallback_port == 0) throw invalid();
        return {std::string(host), *fallback_port};
    }
    unsigned int port = 0;
    const auto [end, error] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (error != std::errc{} || end != port_text.data() + port_text.size() || port == 0 || port > 65535)
        throw invalid();
    return {std::string(host), static_cast<unsigned short>(port)};
}

inline std::string normalize_numeric(std::string_view value) {
    const auto endpoint = parse(value);
    std::ostringstream normalized;
    normalized << boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(endpoint.host), endpoint.port);
    return normalized.str();
}

}
