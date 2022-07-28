#include "../../event_class/event_class.h"

#ifdef __NR_seccomp

#include <linux/seccomp.h>

TEST(SyscallExit, seccompX)
{
	auto evt_test = new event_test(__NR_seccomp, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uint32_t operation = SECCOMP_SET_MODE_FILTER;
	uint32_t flags = 0;
	void* args = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "seccomp", syscall(__NR_seccomp, operation, flags, args));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif