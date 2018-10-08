set( SRC_FILES iftable.c libnfnetlink.c rtnl.c )

add_library(LIBNFNETLINK STATIC ${SRC_FILES})

target_include_directories(LIBNFNETLINK PUBLIC ${PROJECT_SOURCE_DIR}/include)