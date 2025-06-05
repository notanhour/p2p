# P2P
Защищенный одно-пиринговый чат на C++ с использованием Boost.Asio и OpenSSL.

## Функционал
- Прямое соединение двух пользователей (P2P)
- Шифрование сообщений (RSA для обмена ключами, AES-GCM для сообщений)
- Генерация случайных никнеймов
- Сканирование сети на наличие других пиров
- CLI-интерфейс с командами: подключение, отключение, отправка сообщений, сканирование, справка

## Быстрый старт

### Зависимости
- C++20
- [Boost](https://www.boost.org/)
- [OpenSSL](https://www.openssl.org/)
- [nlohmann/json](https://github.com/nlohmann/json)
- CMake 3.30+

### Сборка
```sh
mkdir -p build
cd build
cmake ..
make
```

### Запуск
```sh
./P2P --port <порт>
```

## Комманды в чате
- `connect <host> <port>` — подключиться к другому пиру
- `disconnect` — отключиться от текущего пира
- `send <message>` — отправить текстовое сообщение
- `scan` — найти доступные пиры в сети
- `help` — показать справку по командам
- `quit` — выйти из программы

## Принципы работы
- Пир слушает свой порт и принимает входящие соединения.
- Настройка защищенного канала — передача RSA-ключей.
- AES-ключ генерируется случайно и передается в зашифрованном виде.
- Все сообщения шифруются с помощью AES-GCM.
- Для поиска других пиров реализовано сканирование диапазона портов на всех доступных IP-адресах (loopback или локальных), в зависимости от сборки.

## Структура проекта
- `src/` — исходный код
- `include/` — заголовочные файлы
- `CMakeLists.txt` — сборка через CMake

## Замечания
- Для сканирования loopback-сети используется localhost. Для работы в локальной сети соберите проект без макроса `USE_LOCALHOST` в `CMakeLists.txt` и настройте сетевой интерфейс в файле `include/network/netscan.hpp`.
- Для работы сканирования локальной сети требуются arp-scan и права sudo.
- Для быстрого поиска пиров в сети программа ограничивает диапазон проверяемых портов: 8080-8100. Если пир запущен на порту вне этого диапазона, он не будет найден во время сканирования.

## Лицензия
Этот проект распространяется под лицензией MIT:
```plaintext
Copyright (c) 2025 Nikolai Nazarov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
