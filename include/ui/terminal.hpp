#pragma once

#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <termios.h>
#include <vector>

namespace ui {

enum class Style { normal, heading, muted, success, warning, error, incoming, outgoing, command, listing, details, index };

class Terminal {
private:
    bool interactive;
    bool colored;
    termios saved_attributes{};
    std::atomic<bool> stopped{false};
    std::mutex mutex;
    std::string prompt = "> ";
    std::string draft;
    std::size_t cursor = 0;
    bool reading = false;
    std::size_t rendered_rows = 0;
    std::size_t rendered_cursor_row = 0;
    bool confirming = false;
    std::string command_draft;
    std::size_t command_cursor = 0;
    std::vector<std::string> history;
    std::size_t history_index = 0;
    std::string saved_draft;

    void redraw();
    void clear_input();
    bool composing_message() const;
    void edit(const std::string& key);
    void print(std::string_view text, Style style);

public:
    Terminal();
    ~Terminal();
    Terminal(const Terminal&) = delete;
    Terminal& operator=(const Terminal&) = delete;
    void write(std::string_view text, Style style = Style::normal);
    void echo_command(std::string_view text);
    void request_trust(const std::string& endpoint, const std::string& fingerprint);
    void finish_trust();
    std::optional<std::string> read_line();
    void stop();
};

}
