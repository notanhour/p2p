cmake_minimum_required(VERSION 3.30)
project(p2p LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS program_options CONFIG)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED CONFIG)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(AVAHI REQUIRED IMPORTED_TARGET avahi-client)

add_library(p2p_core
    src/network/peer.cpp
    src/crypto/encryption.cpp
    src/storage/state.cpp
)
target_include_directories(p2p_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(p2p_core PUBLIC
    Boost::headers
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
    Threads::Threads
)

add_library(p2p_discovery src/network/discovery.cpp)
target_include_directories(p2p_discovery PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(p2p_discovery PUBLIC Boost::headers Threads::Threads PRIVATE PkgConfig::AVAHI)

add_executable(p2p src/main.cpp src/ui/terminal.cpp)
target_link_libraries(p2p PRIVATE p2p_core p2p_discovery Boost::program_options)

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
