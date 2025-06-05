#ifndef NETSCAN_HPP
#define NETSCAN_HPP

#include <vector>
#include <string>
#include <utility>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <cstdio>
#include <stdexcept>
#include <algorithm>

namespace network {
    
    const std::string LAN_INTERFACE = "wlp2s0"; // Измените на имя вашего LAN интерфейса

    inline std::string get_interface_ip() {    
        struct ifaddrs* ifaddr = nullptr;
        getifaddrs(&ifaddr);

        std::string result;
        
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {

#ifdef USE_LOCALHOST
                if (!(ifa->ifa_flags & IFF_LOOPBACK)) continue;
#else
                if (std::string(ifa->ifa_name) != LAN_INTERFACE) continue;
#endif

                char ip[INET_ADDRSTRLEN];
                auto* addr = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
                inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
                result = ip;
                break;
            }
        }

        freeifaddrs(ifaddr);
        return result;
    }

    inline std::vector<std::string> get_hosts() {
        #ifdef USE_LOCALHOST
            return {"127.0.0.1"};
        #endif

        std::vector<std::string> hosts;
        std::string cmd = "sudo arp-scan --interface=" + LAN_INTERFACE + " --localnet | grep -v 'Interface:' | grep -v 'Starting' | grep -v '^$' | grep -v 'packets' | grep -v 'Ending' | awk '{print $1}'";

        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            throw std::runtime_error("Failed to run arp-scan command");
        }

        char buf[16];
        while (fgets(buf, sizeof(buf), pipe) != nullptr) {
            std::string ip(buf);
            ip.erase(std::remove(ip.begin(), ip.end(), '\n'), ip.end());
            if (ip.size() > 0) {
                hosts.push_back(ip);
            }
        }

        pclose(pipe);
        return hosts;
    }

}

#endif