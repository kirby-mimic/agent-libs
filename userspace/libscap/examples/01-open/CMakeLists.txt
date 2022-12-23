include_directories("../../../common")
include_directories("../../")

add_executable(scap-open
	${PROJECT_SOURCE_DIR}/../libhotpot/hotpot.c
	scap_open.c)

target_link_libraries(scap-open
	scap)
