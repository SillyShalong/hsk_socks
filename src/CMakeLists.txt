if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    include_directories(/opt/homebrew/Cellar/libev/4.33/include)
endif()
find_library(LIBEV libev.a)
add_executable(Socks5Server main.cc socks5_server.cc sockutils.cc util.cc)
target_link_libraries(Socks5Server ${LIBEV})
