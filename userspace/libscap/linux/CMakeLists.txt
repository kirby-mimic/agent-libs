add_library(scap_platform scap_procs.c scap_fds.c scap_userlist.c scap_iflist.c scap_ppm_sc.c)
target_link_libraries(scap_platform scap_error)
set_scap_target_properties(scap_platform)
