cmake_minimum_required(VERSION 3.28)
cmake_policy(SET CMP0167 NEW) # Используем новую политику для поиска компонентов Boost

project(P2P)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Находим необходимые пакеты
find_package(Boost REQUIRED COMPONENTS system program_options CONFIG)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Добавляем исполняемый файл
add_executable(P2P
    src/main.cpp
    src/network/peer.cpp
    src/crypto/encryption.cpp
)

# Флаг для использования localhost
target_compile_definitions(P2P PRIVATE USE_LOCALHOST)

# Подключаем директории
target_include_directories(P2P PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Связываем библиотеки
target_link_libraries(P2P PRIVATE
    Boost::system
    Boost::program_options
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)