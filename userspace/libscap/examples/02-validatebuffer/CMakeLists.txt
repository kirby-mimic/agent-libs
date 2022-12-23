include_directories("../../../common")
include_directories("../..")

add_executable(scap-validatebuffer
	${PROJECT_SOURCE_DIR}/../libhotpot/hotpot.c
	test.c)

target_link_libraries(scap-validatebuffer
	scap)
