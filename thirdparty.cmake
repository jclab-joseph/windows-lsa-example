if (NOT TARGET plog)
    message("plog: Download")
    FetchContent_Declare(
            plog
            URL https://github.com/SergiusTheBest/plog/archive/refs/tags/1.1.6.tar.gz
            URL_HASH SHA256=99fbb43772f92664ff086166fdff75cc437e9e50e74efec2fba80765fa6b67ae
    )
    FetchContent_GetProperties(plog)
    if (NOT plog_POPULATED)
        FetchContent_Populate(plog)
        add_subdirectory(${plog_SOURCE_DIR} ${plog_BINARY_DIR})
    endif ()
endif ()
