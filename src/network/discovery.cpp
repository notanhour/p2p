#include <network/discovery.hpp>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>
#include <avahi-common/alternative.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/simple-watch.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <tuple>

namespace network {
namespace asio = boost::asio;

struct Discovery::Impl {
    using ServiceKey = std::tuple<AvahiIfIndex, AvahiProtocol, std::string, std::string, std::string>;
    static constexpr const char* service_type = "_p2p-chat._tcp";
    static constexpr std::size_t max_services = 256;
    asio::any_io_executor executor;
    std::string instance;
    unsigned short port;
    AvahiSimplePoll* poll;
    AvahiClient* client = nullptr;
    AvahiEntryGroup* group = nullptr;
    AvahiServiceBrowser* browser = nullptr;
    std::map<ServiceKey, AvahiServiceResolver*> resolvers;
    std::thread worker;
    std::atomic<bool> stopped{false};
    bool failed = false;
    unsigned int collisions = 0;
    bool discovering = false;
    std::mutex mutex;
    std::condition_variable retry;
    struct ResolvedAddress {
        std::string address;
        unsigned short port;
    };
    std::map<ServiceKey, ResolvedAddress> peers;
    std::string error = "Avahi is not ready. Start avahi-daemon to enable discovery.";

    Impl(asio::any_io_executor executor, std::string instance, unsigned short port)
        : executor(std::move(executor)), instance(std::move(instance)), port(port), poll(avahi_simple_poll_new()) {
        if (!poll) throw std::runtime_error("Cannot create the Avahi event loop");
    }

    ~Impl() {
        stop();
        if (worker.joinable()) worker.join();
        avahi_simple_poll_free(poll);
    }

    void stop() {
        stopped.store(true);
        avahi_simple_poll_wakeup(poll);
        retry.notify_all();
    }

    void fail(const std::string& message) {
        failed = true;
        std::lock_guard lock(mutex);
        error = "Avahi discovery unavailable: " + message + ". Check avahi-daemon.";
        peers.clear();
    }

    // Исключения из обработчиков завершают попытку подключения, не выходя через границу C API.
    template<class F> void callback(F operation) noexcept {
        try { operation(); }
        catch (const std::exception& exception) {
            try { fail(exception.what()); } catch (...) { failed = true; }
        } catch (...) {
            try { fail("Callback failed"); } catch (...) { failed = true; }
        }
    }

    void clear_services() {
        for (const auto& [key, resolver] : resolvers) avahi_service_resolver_free(resolver);
        resolvers.clear();
        if (browser) avahi_service_browser_free(browser);
        browser = nullptr;
        std::lock_guard lock(mutex);
        peers.clear();
    }

    void rename_service(AvahiClient* current) {
        if (++collisions > 8) {
            fail("Cannot choose a unique service name");
            return;
        }
        char* alternative = avahi_alternative_service_name(instance.c_str());
        if (!alternative) throw std::bad_alloc();
        std::unique_ptr<char, decltype(&avahi_free)> name(alternative, avahi_free);
        instance = name.get();
        avahi_entry_group_reset(group);
        publish(current);
    }

    static void group_callback(AvahiEntryGroup* entry, AvahiEntryGroupState state, void* data) {
        auto& self = *static_cast<Impl*>(data);
        self.callback([&] {
            self.group = entry;
            if (state == AVAHI_ENTRY_GROUP_COLLISION) self.rename_service(avahi_entry_group_get_client(entry));
            else if (state == AVAHI_ENTRY_GROUP_FAILURE)
                self.fail(avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(entry))));
        });
    }

    void publish(AvahiClient* current) {
        if (!group) group = avahi_entry_group_new(current, group_callback, this);
        if (!group) { fail(avahi_strerror(avahi_client_errno(current))); return; }
        if (!avahi_entry_group_is_empty(group)) return;
        const int added = avahi_entry_group_add_service(group, AVAHI_IF_UNSPEC, AVAHI_PROTO_INET,
            static_cast<AvahiPublishFlags>(0), instance.c_str(), service_type, "local", nullptr, port,
            static_cast<const char*>(nullptr));
        if (added == AVAHI_ERR_COLLISION) { rename_service(current); return; }
        if (added < 0) { fail(avahi_strerror(added)); return; }
        const int committed = avahi_entry_group_commit(group);
        if (committed < 0) fail(avahi_strerror(committed));
    }

    static void resolve_callback(AvahiServiceResolver* resolver, AvahiIfIndex interface, AvahiProtocol protocol,
        AvahiResolverEvent event, const char* name, const char* type, const char* domain, const char*,
        const AvahiAddress* address, uint16_t port, AvahiStringList*, AvahiLookupResultFlags, void* data) {
        auto& self = *static_cast<Impl*>(data);
        self.callback([&] {
            const ServiceKey key{interface, protocol, name, type, domain};
            const auto pending = self.resolvers.find(key);
            if (pending == self.resolvers.end() || pending->second != resolver) return;
            std::lock_guard lock(self.mutex);
            if (event == AVAHI_RESOLVER_FOUND && address && address->proto == AVAHI_PROTO_INET && port != 0) {
                char text[AVAHI_ADDRESS_STR_MAX];
                if (avahi_address_snprint(text, sizeof(text), address)) self.peers[key] = {text, port};
            } else self.peers.erase(key);
        });
    }

    static void browse_callback(AvahiServiceBrowser* browser, AvahiIfIndex interface, AvahiProtocol protocol,
        AvahiBrowserEvent event, const char* name, const char* type, const char* domain,
        AvahiLookupResultFlags flags, void* data) {
        auto& self = *static_cast<Impl*>(data);
        self.callback([&] {
            if (event == AVAHI_BROWSER_FAILURE) {
                self.fail(avahi_strerror(avahi_client_errno(avahi_service_browser_get_client(browser))));
                return;
            }
            if (event != AVAHI_BROWSER_NEW && event != AVAHI_BROWSER_REMOVE) return;
            const ServiceKey key{interface, protocol, name, type, domain};
            if (event == AVAHI_BROWSER_REMOVE) {
                const auto found = self.resolvers.find(key);
                if (found != self.resolvers.end()) {
                    avahi_service_resolver_free(found->second);
                    self.resolvers.erase(found);
                }
                std::lock_guard lock(self.mutex);
                self.peers.erase(key);
            } else if (!(flags & AVAHI_LOOKUP_RESULT_OUR_OWN) && !self.resolvers.contains(key) &&
                       self.resolvers.size() < max_services) {
                auto* resolver = avahi_service_resolver_new(avahi_service_browser_get_client(browser),
                    interface, protocol, name, type, domain, AVAHI_PROTO_INET,
                    static_cast<AvahiLookupFlags>(AVAHI_LOOKUP_USE_MULTICAST), resolve_callback, &self);
                if (resolver) self.resolvers.emplace(key, resolver);
            }
        });
    }

    static void client_callback(AvahiClient* current, AvahiClientState state, void* data) {
        auto& self = *static_cast<Impl*>(data);
        self.callback([&] {
            if (state == AVAHI_CLIENT_S_RUNNING) {
                self.publish(current);
                if (self.failed) return;
                if (!self.browser) self.browser = avahi_service_browser_new(current, AVAHI_IF_UNSPEC, AVAHI_PROTO_INET,
                    service_type, "local", static_cast<AvahiLookupFlags>(AVAHI_LOOKUP_USE_MULTICAST), browse_callback, &self);
                if (!self.browser) { self.fail(avahi_strerror(avahi_client_errno(current))); return; }
                std::lock_guard lock(self.mutex);
                self.error.clear();
            } else if (state == AVAHI_CLIENT_FAILURE) {
                self.fail(avahi_strerror(avahi_client_errno(current)));
            } else {
                self.clear_services();
                if (self.group) avahi_entry_group_reset(self.group);
                std::lock_guard lock(self.mutex);
                self.error = "Avahi is not ready. Start avahi-daemon to enable discovery.";
            }
        });
    }

    void run() noexcept {
        while (!stopped.load()) {
            failed = false;
            int result = 0;
            try {
                // Все обращения к Avahi выполняются в рабочем потоке, включая создание клиента D-Bus.
                client = avahi_client_new(avahi_simple_poll_get(poll), AVAHI_CLIENT_NO_FAIL, client_callback, this, &result);
                if (!client) fail(avahi_strerror(result));
                while (client && !failed && !stopped.load()) {
                    if (avahi_simple_poll_iterate(poll, -1) != 0) { fail("Event loop stopped"); break; }
                }
            } catch (const std::exception& exception) {
                try { fail(exception.what()); } catch (...) { failed = true; }
            }
            clear_services();
            if (client) avahi_client_free(client);
            client = nullptr;
            group = nullptr;
            collisions = 0;
            // После восстановления системной службы объявления и поиск запускаются повторно.
            std::unique_lock lock(mutex);
            retry.wait_for(lock, std::chrono::seconds(1), [&] { return stopped.load(); });
        }
    }

    std::vector<DiscoveredPeer> snapshot() {
        std::lock_guard lock(mutex);
        if (!error.empty()) throw std::runtime_error(error);
        using Identity = std::tuple<std::string, std::string, std::string, unsigned short>;
        std::map<Identity, DiscoveredPeer> grouped;
        // Интерфейс не входит в идентификатор сервиса: его адреса принадлежат одному объявлению.
        for (const auto& [key, peer] : peers) {
            const Identity identity{std::get<2>(key), std::get<3>(key), std::get<4>(key), peer.port};
            auto [entry, inserted] = grouped.try_emplace(identity, DiscoveredPeer{std::get<2>(key), peer.port, {}});
            entry->second.addresses.push_back(peer.address);
        }
        std::vector<DiscoveredPeer> result;
        for (auto& [identity, peer] : grouped) {
            // На одном компьютере петлевой адрес дает прямой маршрут без выбора сетевого интерфейса.
            std::sort(peer.addresses.begin(), peer.addresses.end(), [](const auto& left, const auto& right) {
                const bool left_loopback = asio::ip::make_address(left).is_loopback();
                const bool right_loopback = asio::ip::make_address(right).is_loopback();
                if (left_loopback != right_loopback) return left_loopback;
                return left < right;
            });
            peer.addresses.erase(std::unique(peer.addresses.begin(), peer.addresses.end()), peer.addresses.end());
            result.push_back(std::move(peer));
        }
        return result;
    }
};

Discovery::Discovery(asio::any_io_executor executor, std::string instance, unsigned short port)
    : impl(std::make_shared<Impl>(std::move(executor), std::move(instance), port)) {}

Discovery::~Discovery() { stop(); }

void Discovery::start() {
    if (impl->worker.joinable() || impl->stopped.load()) throw std::logic_error("Discovery can only be started once");
    impl->worker = std::thread([state = impl.get()] { state->run(); });
}

void Discovery::stop() { impl->stop(); }

asio::awaitable<std::vector<DiscoveredPeer>> Discovery::discover() {
    auto state = impl;
    if (state->stopped.load()) throw std::runtime_error("Discovery stopped");
    if (state->discovering) throw std::runtime_error("Discovery is in progress");
    state->discovering = true;
    struct Reset {
        bool& discovering;
        ~Reset() { discovering = false; }
    } reset{state->discovering};
    // Окно поиска дает mDNS время получить объявления, сохраняя отзывчивость CLI и чата.
    asio::steady_timer timer(state->executor, std::chrono::seconds(2));
    co_await timer.async_wait(asio::use_awaitable);
    if (state->stopped.load()) throw std::runtime_error("Discovery stopped");
    co_return state->snapshot();
}

}
