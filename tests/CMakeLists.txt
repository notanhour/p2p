# Сборка тестовых программ
add_executable(p2p_crypto_tests crypto.cpp)
target_link_libraries(p2p_crypto_tests PRIVATE p2p_core)

add_executable(p2p_network_tests network.cpp)
target_link_libraries(p2p_network_tests PRIVATE p2p_core)

add_executable(p2p_identity_storage_tests identity_storage.cpp)
target_link_libraries(p2p_identity_storage_tests PRIVATE p2p_core)

# Регистрация проверок C++
add_test(NAME encryption_and_keys COMMAND p2p_crypto_tests)
add_test(NAME endpoint_addresses COMMAND p2p_network_tests addresses)
add_test(NAME frame_buffer_and_limits COMMAND p2p_network_tests framing)
add_test(NAME peer_authentication COMMAND p2p_network_tests handshake)
add_test(NAME identity_and_known_peers COMMAND p2p_identity_storage_tests)

set_tests_properties(
    encryption_and_keys endpoint_addresses frame_buffer_and_limits
    peer_authentication identity_and_known_peers
    PROPERTIES TIMEOUT 30
)

# Проверки CLI и обнаружения пиров через Python
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME chat_cli COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/chat_cli.py $<TARGET_FILE:p2p>)
    add_test(NAME terminal_interaction COMMAND ${Python3_EXECUTABLE} -B
        ${CMAKE_CURRENT_SOURCE_DIR}/terminal.py $<TARGET_FILE:p2p>)
    add_test(NAME cli_default_port COMMAND ${Python3_EXECUTABLE} -B
        ${CMAKE_CURRENT_SOURCE_DIR}/chat_cli.py $<TARGET_FILE:p2p> default-port)
    add_test(NAME discovery_without_avahi COMMAND ${Python3_EXECUTABLE} -B
        ${CMAKE_CURRENT_SOURCE_DIR}/discovery.py $<TARGET_FILE:p2p> unavailable)
    add_test(NAME mdns_discovery COMMAND ${Python3_EXECUTABLE} -B
        ${CMAKE_CURRENT_SOURCE_DIR}/discovery.py $<TARGET_FILE:p2p> available)

    set_tests_properties(chat_cli PROPERTIES TIMEOUT 90)
    set_tests_properties(terminal_interaction PROPERTIES TIMEOUT 30)
    set_tests_properties(cli_default_port PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77)
    set_tests_properties(discovery_without_avahi mdns_discovery PROPERTIES TIMEOUT 45)
    set_tests_properties(mdns_discovery PROPERTIES SKIP_RETURN_CODE 77)
endif()
