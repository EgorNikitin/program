set( SRC_FILES rules.cpp )

add_library(RULES STATIC ${SRC_FILES})

target_include_directories(RULES PUBLIC ${PROJECT_SOURCE_DIR}/include)