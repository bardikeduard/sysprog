cmake_minimum_required(VERSION 3.16)

project(lab05 C)

set(HEADERS array.h chat.h chat_client.h msg_node.h chat_server.h)
set(COMMON_SOURCES chat.c ${HEADERS})# ../utils/heap_help/heap_help.c)
set(CLIENT_SOURCES chat_client.c)
set(SERVER_SOURCES chat_server.c)
set(TEST_SOURCES ${CLIENT_SOURCES} ${SERVER_SOURCES} test.c ../utils/unit.c)

add_executable(client ${COMMON_SOURCES} ${CLIENT_SOURCES} chat_client_exe.c)
add_executable(server ${COMMON_SOURCES} ${SERVER_SOURCES} chat_server_exe.c)
add_executable(test ${COMMON_SOURCES} ${TEST_SOURCES})

include_directories(../utils)
add_compile_options(-Werror -Wall -Wextra -Wno-gnu-folding-constant -ldl -rdynamic)
