cmake_minimum_required(VERSION 3.16)
project(proxy_chain LANGUAGES C)

if (NOT WIN32)
enable_testing()
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

set(PROXY_CORE_SOURCES
	src/queue.c
	src/vector.c
	src/logger.c
	src/thread_event_loop.c
	src/socks5_proxy.c
	src/config.c)

if (WIN32)
	list(APPEND PROXY_CORE_SOURCES src/event_loop_win.c)
else()
	pkg_check_modules(LIBURING REQUIRED liburing)
	include_directories(${LIBURING_INCLUDE_DIRS})
	link_directories(${LIBURING_LIBRARY_DIRS})
	list(APPEND PROXY_CORE_SOURCES src/event_loop.c)
endif()

add_library(proxy_core STATIC ${PROXY_CORE_SOURCES})
target_include_directories(proxy_core PUBLIC src)
if (WIN32)
    target_link_libraries(proxy_core PUBLIC Threads::Threads ws2_32)
else()
    target_link_libraries(proxy_core PUBLIC ${LIBURING_LIBRARIES} Threads::Threads)
endif()

add_executable(proxy_chain app/main.c)

if (NOT WIN32)
# Export symbols for backtrace_symbols to resolve names
set_target_properties(proxy_chain PROPERTIES LINK_FLAGS "-rdynamic")
endif()

target_include_directories(proxy_chain PRIVATE src)
target_link_libraries(proxy_chain PRIVATE proxy_core)

if (NOT WIN32)
add_subdirectory(tests)
endif()

install(TARGETS proxy_chain RUNTIME DESTINATION bin)
install(FILES packaging/proxy-chain.service DESTINATION lib/systemd/system)
install(FILES packaging/proxy-chain.conf.example DESTINATION etc/proxy-chain RENAME proxy-chain.conf)

include(InstallRequiredSystemLibraries)
set(CPACK_PACKAGE_NAME "proxy-chain")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_PACKAGE_CONTACT "admin@example.com")
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "proxy-chain")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://example.com/proxy-chain")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "liburing1")
include(CPack)
