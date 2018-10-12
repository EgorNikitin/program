set( SRC_FILES utils.cpp )

add_library(UTILS STATIC ${SRC_FILES})

target_include_directories(UTILS PUBLIC ${PROJECT_SOURCE_DIR}/include)