#include <ui/terminal.hpp>
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cwchar>
#include <cstdlib>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <unistd.h>
#include <utility>

namespace ui {
namespace {

std::size_t previous(const std::string& text, std::size_t position) {
    if (position == 0) return 0;
    --position;
    while (position > 0 && (static_cast<unsigned char>(text[position]) & 0xc0) == 0x80) --position;
    return position;
}

std::size_t next(const std::string& text, std::size_t position) {
    if (position == text.size()) return position;
    ++position;
    while (position < text.size() && (static_cast<unsigned char>(text[position]) & 0xc0) == 0x80) ++position;
    return position;
}

std::size_t columns(std::string_view text) {
    std::size_t result = 0;
    while (!text.empty()) {
        std::mbstate_t state{};
        wchar_t character;
        auto length = std::mbrtowc(&character, text.data(), text.size(), &state);
        if (length == static_cast<std::size_t>(-1) || length == static_cast<std::size_t>(-2) || length == 0) {
            length = 1;
            ++result;
        } else {
            result += std::max(0, ::wcwidth(character));
        }
        text.remove_prefix(length);
    }
    return result;
}

std::string printable(std::string_view text) {
    std::string result;
    for (const unsigned char character : text) {
        if (character == '\t') result += "    ";
        else if (character == '\n' || (character >= 32 && character != 127)) result += character;
    }
    return result;
}

std::string wrap_message(const std::string& text, std::size_t width) {
    const auto separator = text.find(": ");
    if (separator == std::string::npos || width < 4) return text;
    const auto label_end = separator + 2;
    const auto label_width = columns(std::string_view(text).substr(0, label_end));
    // Длинное имя не должно занимать всю ширину продолжений сообщения.
    const auto indent = label_width <= width - 2 ? label_width : 2;
    auto available = label_width < width ? width - label_width : 0;
    auto position = label_end;
    auto result = text.substr(0, label_end);
    while (position < text.size()) {
        auto end = position;
        auto space = std::string::npos;
        std::size_t occupied = 0;
        while (end < text.size() && text[end] != '\n') {
            const auto after = next(text, end);
            const auto character_width = columns(std::string_view(text).substr(end, after - end));
            if (occupied + character_width > available) break;
            if (text[end] == ' ') space = end;
            occupied += character_width;
            end = after;
        }
        const bool newline = end < text.size() && text[end] == '\n';
        auto following = newline ? end + 1 : end;
        // Предпочитаем границу слова, сохраняя целыми символы UTF-8.
        if (!newline && end < text.size() && space != std::string::npos && space > position) {
            end = space;
            following = space + 1;
            while (following < text.size() && text[following] == ' ') ++following;
        }
        result.append(text, position, end - position);
        position = following;
        if (position == text.size() && !newline) break;
        result += '\n';
        if (position < text.size() && text[position] != '\n') result.append(indent, ' ');
        available = width - indent;
    }
    return result;
}

}

Terminal::Terminal() : interactive(::isatty(STDIN_FILENO) && ::isatty(STDOUT_FILENO)) {
    const auto no_color = std::getenv("NO_COLOR");
    const auto term = std::getenv("TERM");
    colored = interactive && !(no_color && *no_color) && !(term && std::string_view(term) == "dumb");
    if (!interactive) return;
    if (::tcgetattr(STDIN_FILENO, &saved_attributes) != 0) throw std::runtime_error("Cannot read terminal settings");
    auto attributes = saved_attributes;
    attributes.c_lflag &= ~(ICANON | ECHO | IEXTEN);
    attributes.c_iflag &= ~(IXON | ICRNL | INLCR | IGNCR);
    attributes.c_cc[VMIN] = 1;
    attributes.c_cc[VTIME] = 0;
    if (::tcsetattr(STDIN_FILENO, TCSANOW, &attributes) != 0) throw std::runtime_error("Cannot configure terminal input");
}

Terminal::~Terminal() {
    if (interactive) {
        if (reading) std::cout << '\n' << std::flush;
        ::tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes);
    }
}

void Terminal::clear_input() {
    if (!interactive || !rendered_rows) return;
    std::cout << '\r';
    if (rendered_cursor_row) std::cout << "\033[" << rendered_cursor_row << 'A';
    for (std::size_t row = 0; row < rendered_rows; ++row) {
        std::cout << "\033[2K";
        if (row + 1 < rendered_rows) std::cout << "\033[1B";
    }
    if (rendered_rows > 1) std::cout << "\033[" << rendered_rows - 1 << 'A';
    rendered_rows = 0;
    rendered_cursor_row = 0;
}

bool Terminal::composing_message() const {
    if (confirming) return false;
    const auto begin = draft.find_first_not_of(" \t");
    if (begin == std::string::npos || draft.compare(begin, 4, "send") != 0) return false;
    return begin + 4 == draft.size() || std::string_view(" \t\n").find(draft[begin + 4]) != std::string_view::npos;
}

void Terminal::print(std::string_view text, Style style) {
    if (!colored || style == Style::normal || text.empty()) {
        std::cout << text;
        return;
    }
    if (style == Style::listing || style == Style::details) {
        bool first = true;
        while (!text.empty()) {
            const auto end = text.find('\n');
            const auto line = text.substr(0, end);
            auto prefix = std::string_view::npos;
            if (style == Style::listing && line.starts_with('[')) {
                const auto index = line.find(']');
                if (index != std::string_view::npos) prefix = index + 1;
            } else if (style == Style::details) {
                prefix = line.find(" — ");
                if (prefix == std::string_view::npos) {
                    const auto colon = line.find(':');
                    if (colon != std::string_view::npos) prefix = colon + 1;
                }
            }
            if (prefix != std::string_view::npos) {
                print(line.substr(0, prefix), style == Style::listing ? Style::index : Style::heading);
                std::cout << line.substr(prefix);
            } else print(line, first ? Style::heading : Style::normal);
            if (end == std::string_view::npos) break;
            std::cout << '\n';
            text.remove_prefix(end + 1);
            first = false;
        }
        return;
    }
    std::string_view color;
    switch (style) {
        case Style::heading:
        case Style::incoming:
        case Style::command: color = "\033[38;5;110m"; break;
        case Style::muted: color = "\033[2m"; break;
        case Style::success: color = "\033[38;5;114m"; break;
        case Style::warning: color = "\033[38;5;186m"; break;
        case Style::error: color = "\033[38;5;167m"; break;
        case Style::outgoing: color = "\033[38;5;183m"; break;
        case Style::index: color = "\033[1;38;5;110m"; break;
        default: break;
    }
    std::size_t prefix = text.size();
    // Цвет имени не распространяется на текст сообщения и последующие строки.
    if (style == Style::incoming || style == Style::outgoing) {
        const auto separator = text.find(": ");
        if (separator != std::string_view::npos) prefix = separator + 1;
    } else if (style == Style::command) prefix = std::min<std::size_t>(2, text.size());
    std::cout << color << text.substr(0, prefix) << "\033[0m" << text.substr(prefix);
}

void Terminal::redraw() {
    if (!interactive || !reading) return;
    clear_input();
    winsize size{};
    ::ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);
    const std::size_t width = size.ws_col > 1 ? size.ws_col - 1 : 79;
    const std::size_t height = size.ws_row > 2 ? size.ws_row - 2 : 1;
    std::vector<std::size_t> starts{0};
    for (std::size_t i = 0; i < draft.size(); ++i) if (draft[i] == '\n') starts.push_back(i + 1);
    const auto active = static_cast<std::size_t>(std::upper_bound(starts.begin(), starts.end(), cursor) - starts.begin() - 1);
    // Видимая область ограничена высотой терминала и следует за курсором.
    const auto first = active >= height ? active - height + 1 : 0;
    const auto last = std::min(starts.size(), first + height);
    std::size_t cursor_column = 0;
    for (auto row = first; row < last; ++row) {
        const auto prefix = row == 0 ? prompt : "  ";
        const auto limit = row + 1 < starts.size() ? starts[row + 1] - 1 : draft.size();
        const auto line = prefix + draft.substr(starts[row], limit - starts[row]);
        const auto position = row == active ? prefix.size() + cursor - starts[row] : 0;
        std::size_t begin = 0;
        auto column = columns(std::string_view(line).substr(0, position));
        // Длинные строки прокручиваются по горизонтали, не вызывая переноса терминалом.
        while (column >= width && begin < position) {
            const auto following = next(line, begin);
            column -= columns(std::string_view(line).substr(begin, following - begin));
            begin = following;
        }
        std::size_t end = begin;
        std::size_t occupied = 0;
        while (end < line.size()) {
            const auto following = next(line, end);
            const auto character_width = columns(std::string_view(line).substr(end, following - end));
            if (occupied + character_width > width) break;
            occupied += character_width;
            end = following;
        }
        if (row != first) std::cout << '\n';
        std::cout << "\r\033[2K";
        // Управляющие последовательности цвета не участвуют в расчете ширины и положения курсора.
        const auto prefix_end = std::min(end, prefix.size());
        if (begin < prefix_end) print(std::string_view(line).substr(begin, prefix_end - begin),
                                      confirming ? Style::warning : Style::heading);
        const auto text_begin = std::max(begin, prefix_end);
        std::cout << std::string_view(line).substr(text_begin, end - text_begin);
        if (row == active) cursor_column = column;
    }
    rendered_rows = last - first;
    rendered_cursor_row = active - first;
    if (last - active > 1) std::cout << "\033[" << last - active - 1 << 'A';
    std::cout << '\r';
    if (cursor_column) std::cout << "\033[" << cursor_column << 'C';
    std::cout << std::flush;
}

void Terminal::write(std::string_view text, Style style) {
    std::lock_guard lock(mutex);
    clear_input();
    auto output = printable(text);
    if (interactive && (style == Style::incoming || style == Style::outgoing)) {
        winsize size{};
        ::ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);
        const std::size_t width = size.ws_col > 1 ? size.ws_col - 1 : 79;
        output = wrap_message(output, width);
    }
    print(output, style);
    std::cout << '\n';
    redraw();
    std::cout << std::flush;
}

void Terminal::echo_command(std::string_view text) {
    if (interactive) write("> " + std::string(text), Style::command);
}

void Terminal::request_trust(const std::string& endpoint, const std::string& fingerprint) {
    std::lock_guard lock(mutex);
    clear_input();
    // Подтверждение получает отдельную строку ввода, сохраняя незавершенную команду.
    confirming = true;
    command_draft = std::exchange(draft, {});
    command_cursor = std::exchange(cursor, 0);
    std::cout << '\n';
    print("Unknown peer · " + printable(endpoint), Style::warning);
    std::cout << '\n';
    print("SHA-256: ", Style::muted);
    std::cout << printable(fingerprint) << "\n\n";
    print("You have 60 seconds to answer.", Style::muted);
    std::cout << '\n';
    prompt = "Trust this peer? Type 'yes' or 'no': ";
    if (interactive) redraw();
    else std::cout << prompt;
    std::cout << std::flush;
}

void Terminal::finish_trust() {
    std::lock_guard lock(mutex);
    if (confirming) {
        draft = std::exchange(command_draft, {});
        cursor = command_cursor;
        confirming = false;
    }
    prompt = "> ";
    redraw();
}

void Terminal::edit(const std::string& key) {
    const auto preceding = cursor ? draft.rfind('\n', cursor - 1) : std::string::npos;
    const auto line_begin = preceding == std::string::npos ? 0 : preceding + 1;
    const auto following = draft.find('\n', cursor);
    const auto line_end = following == std::string::npos ? draft.size() : following;
    if (key == "\033[D") cursor = previous(draft, cursor);
    else if (key == "\033[C") cursor = next(draft, cursor);
    else if (key == "\001" || key == "\033[H" || key == "\033[1~") cursor = line_begin;
    else if (key == "\005" || key == "\033[F" || key == "\033[4~") cursor = line_end;
    else if (key == "\n" || key == "\033\r" || key == "\033\n" || key == "\033[13;2u" || key == "\033[27;2;13~") {
        if (composing_message()) draft.insert(cursor++, 1, '\n');
    } else if (key == "\177" || key == "\b") {
        const auto begin = previous(draft, cursor);
        draft.erase(begin, cursor - begin);
        cursor = begin;
    } else if (key == "\033[3~" || key == "\004") draft.erase(cursor, next(draft, cursor) - cursor);
    else if (key == "\025") { draft.erase(line_begin, cursor - line_begin); cursor = line_begin; }
    else if (key == "\013") draft.erase(cursor, line_end - cursor);
    else if (key == "\027") {
        auto begin = cursor;
        while (begin > line_begin && draft[begin - 1] == ' ') --begin;
        while (begin > line_begin && draft[begin - 1] != ' ') begin = previous(draft, begin);
        draft.erase(begin, cursor - begin);
        cursor = begin;
    } else if (key == "\033[A" || key == "\033[B") {
        if (draft.find('\n') != std::string::npos) {
            const auto desired = columns(std::string_view(draft).substr(line_begin, cursor - line_begin));
            std::size_t target_begin = line_begin;
            std::size_t target_end = line_end;
            if (key == "\033[A" && line_begin) {
                target_end = line_begin - 1;
                const auto delimiter = target_end ? draft.rfind('\n', target_end - 1) : std::string::npos;
                target_begin = delimiter == std::string::npos ? 0 : delimiter + 1;
            } else if (key == "\033[B" && line_end < draft.size()) {
                target_begin = line_end + 1;
                target_end = draft.find('\n', target_begin);
                if (target_end == std::string::npos) target_end = draft.size();
            }
            cursor = target_begin;
            std::size_t occupied = 0;
            while (cursor < target_end) {
                const auto after = next(draft, cursor);
                const auto width = columns(std::string_view(draft).substr(cursor, after - cursor));
                if (occupied + width > desired) break;
                occupied += width;
                cursor = after;
            }
            redraw();
            return;
        }
        if (history_index == history.size()) saved_draft = draft;
        if (key == "\033[A" && history_index > 0) --history_index;
        if (key == "\033[B" && history_index < history.size()) ++history_index;
        draft = history_index == history.size() ? saved_draft : history[history_index];
        cursor = draft.size();
    } else if (!key.empty() && static_cast<unsigned char>(key.front()) >= 32 && key.front() != 127) {
        draft.insert(cursor, key);
        cursor += key.size();
    }
    redraw();
}

std::optional<std::string> Terminal::read_line() {
    {
        std::lock_guard lock(mutex);
        reading = true;
        history_index = history.size();
        saved_draft.clear();
        redraw();
    }
    std::string escape;
    std::string utf8;
    std::size_t utf8_length = 0;
    while (!stopped.load()) {
        pollfd input{STDIN_FILENO, POLLIN, 0};
        const int available = ::poll(&input, 1, 100);
        if (available < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("Cannot read terminal input");
        }
        if (!available) { escape.clear(); continue; }
        char character;
        const auto count = ::read(STDIN_FILENO, &character, 1);
        if (count < 0 && errno == EINTR) continue;
        std::lock_guard lock(mutex);
        if (count <= 0 || (interactive && character == '\004' && draft.empty())) {
            reading = false;
            if (interactive) std::cout << '\n' << std::flush;
            if (draft.empty()) return {};
            return std::exchange(draft, {});
        }
        if (interactive && (!escape.empty() || character == '\033')) {
            escape += character;
            if (escape == "\033" || escape == "\033[" || escape == "\033O") continue;
            if (escape.size() < 24 && ((character >= '0' && character <= '9') || character == ';')) continue;
            if (escape.starts_with("\033O")) escape[1] = '[';
            edit(escape);
            escape.clear();
            continue;
        }
        if (interactive && character == '\n' && composing_message()) {
            edit("\n");
            continue;
        }
        if (character == '\n' || character == '\r') {
            const bool message = composing_message();
            clear_input();
            reading = false;
            if (interactive && !message) {
                print(prompt, confirming ? Style::warning : Style::heading);
                std::cout << draft << '\n';
            }
            std::cout << std::flush;
            auto line = std::exchange(draft, {});
            cursor = 0;
            if (interactive && !line.empty() && line != "yes" && line != "no" &&
                (history.empty() || history.back() != line)) {
                if (history.size() == 100) history.erase(history.begin());
                history.push_back(line);
            }
            return line;
        }
        if (!interactive) { draft += character; continue; }
        {
            const auto byte = static_cast<unsigned char>(character);
            // Символ UTF-8 выводится после получения всех байтов, без промежуточных фрагментов.
            if (!utf8.empty()) {
                if ((byte & 0xc0) == 0x80) {
                    utf8 += character;
                    if (utf8.size() == utf8_length) {
                        edit(utf8);
                        utf8.clear();
                    }
                    continue;
                }
                utf8.clear();
            }
            if (byte >= 0xc2 && byte <= 0xf4) {
                utf8 = character;
                utf8_length = byte < 0xe0 ? 2 : byte < 0xf0 ? 3 : 4;
            } else if (byte < 128) edit(std::string(1, character));
        }
    }
    return {};
}

void Terminal::stop() { stopped.store(true); }

}
