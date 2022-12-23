include_directories(${LIBSCAP_INCLUDE_DIRS} ${PROJECT_SOURCE_DIR}/../libhotpot)
add_library(scap_engine_kmod scap_kmod.c)
target_link_libraries(scap_engine_kmod scap_event_schema scap_engine_util scap_error)
