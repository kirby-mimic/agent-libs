include_directories(${LIBSCAP_INCLUDE_DIRS})
add_library(scap_engine_noop noop.c)
set_scap_target_properties(scap_engine_noop)
