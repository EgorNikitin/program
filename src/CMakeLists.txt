add_subdirectory("extra")
add_subdirectory("libnfnetlink")

set( SRC_FILES libnetfilter_queue.c nlmsg.c )

add_library(SRC STATIC ${SRC_FILES})

target_include_directories(SRC PUBLIC include)

target_link_libraries(SRC PUBLIC EXTRA)
target_link_libraries(SRC PUBLIC LIBNFNETLINK)

