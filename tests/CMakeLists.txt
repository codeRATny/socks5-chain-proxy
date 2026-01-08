enable_testing()

set(TEST_SOURCES
    test_queue.c
    test_vector.c
    test_config.c
    test_logger.c
    test_event_loop.c
    test_thread_event_loop.c
    test_socks5.c
)

find_package(Threads REQUIRED)

foreach(src ${TEST_SOURCES})
    get_filename_component(tname ${src} NAME_WE)
    add_executable(${tname} ${src})
    target_include_directories(${tname} PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(${tname} PRIVATE Threads::Threads proxy_core)
    add_test(NAME ${tname} COMMAND ${tname})
endforeach()
