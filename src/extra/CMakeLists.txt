set( SRC_FILES checksum.c ipv4.c ipv6.c pktbuff.c tcp.c udp.c )

add_library(EXTRA STATIC ${SRC_FILES})

target_include_directories(EXTRA PUBLIC ${PROJECT_SOURCE_DIR}/include)