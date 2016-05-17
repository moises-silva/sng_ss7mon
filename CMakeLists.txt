CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(sng_ss7mon C)

ADD_DEFINITIONS(-ggdb3 -O0 -Wall -Wshadow -Wcast-qual -Wcast-align -Wchar-subscripts -Wmissing-prototypes -Wmissing-declarations)

INCLUDE(CheckIncludeFiles)

SET(CMAKE_REQUIRED_INCLUDES /usr/include/wanpipe)
CHECK_INCLUDE_FILES(libsangoma.h HAVE_LIBSANGOMA_H)

ADD_EXECUTABLE(${PROJECT_NAME} ./src/sng_ss7mon.c ./src/wanpipe_hdlc.c ./src/os.c ./src/os_threadmutex.c)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} sangoma)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} rt)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} m)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} zmq)
IF(NOT WIN32)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} pthread)
INCLUDE_DIRECTORIES(./src/include /usr/include/wanpipe)
ENDIF(NOT WIN32)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION /usr/bin)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_SOURCE_DIR}/config.h)
