/*
 * Access to user system call parameters and results
 *
 * Copyright (C) 2008-2009 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * See asm-generic/syscall.h for descriptions of what we must do here.
 */

#ifndef _ASM_X86_SYSCALL_H
#define _ASM_X86_SYSCALL_H

//#include <uapi/linux/audit.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <asm/asm-offsets.h>	/* For NR_syscalls */
#include <asm/thread_info.h>	/* for TS_COMPAT */
#include <asm/unistd.h>

#ifndef NR_syscalls
#define NR_syscalls (__NR_syscall_max + 1)
#endif

typedef void (*sys_call_ptr_t)(void);
extern const sys_call_ptr_t sys_call_table[];

/*
 * Only the low 32 bits of orig_ax are meaningful, so we return int.
 * This importantly ignores the high bits on 64-bit, so comparisons
 * sign-extend the low 32 bits.
 */
static inline int syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	return regs->orig_rax;
}

static inline void syscall_rollback(struct task_struct *task,
				    struct pt_regs *regs)
{
	regs->rax = regs->orig_rax;
}

static inline long syscall_get_error(struct task_struct *task,
				     struct pt_regs *regs)
{
	unsigned long error = regs->rax;
#ifdef CONFIG_IA32_EMULATION
	/*
	 * TS_COMPAT is set for 32-bit syscall entries and then
	 * remains set until we return to user mode.
	 */
	if (task_thread_info(task)->status & TS_COMPAT)
		/*
		 * Sign-extend the value so (int)-EFOO becomes (long)-EFOO
		 * and will match correctly in comparisons.
		 */
		error = (long) (int) error;
#endif
	return IS_ERR_VALUE(error) ? error : 0;
}

static inline long syscall_get_return_value(struct task_struct *task,
					    struct pt_regs *regs)
{
	return regs->rax;
}

static inline void syscall_set_return_value(struct task_struct *task,
					    struct pt_regs *regs,
					    int error, long val)
{
	regs->rax = (long) error ?: val;
}

#ifdef CONFIG_X86_32

static inline void syscall_get_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 unsigned long *args)
{
	BUG_ON(i + n > 6);
	memcpy(args, &regs->rbx + i, n * sizeof(args[0]));
}

static inline void syscall_set_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 const unsigned long *args)
{
	BUG_ON(i + n > 6);
	memcpy(&regs->rbx + i, args, n * sizeof(args[0]));
}

static inline int syscall_get_arch(void)
{
	return AUDIT_ARCH_I386;
}

#else	 /* CONFIG_X86_64 */

static inline void syscall_get_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 unsigned long *args)
{
# ifdef CONFIG_IA32_EMULATION
	if (task_thread_info(task)->status & TS_COMPAT)
		switch (i) {
		case 0:
			if (!n--) break;
			*args++ = regs->rbx;
		case 1:
			if (!n--) break;
			*args++ = regs->rcx;
		case 2:
			if (!n--) break;
			*args++ = regs->rdx;
		case 3:
			if (!n--) break;
			*args++ = regs->rsi;
		case 4:
			if (!n--) break;
			*args++ = regs->rdi;
		case 5:
			if (!n--) break;
			*args++ = regs->rbp;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
	else
# endif
		switch (i) {
		case 0:
			if (!n--) break;
			*args++ = regs->rdi;
		case 1:
			if (!n--) break;
			*args++ = regs->rsi;
		case 2:
			if (!n--) break;
			*args++ = regs->rdx;
		case 3:
			if (!n--) break;
			*args++ = regs->r10;
		case 4:
			if (!n--) break;
			*args++ = regs->r8;
		case 5:
			if (!n--) break;
			*args++ = regs->r9;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
}

static inline void syscall_set_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 const unsigned long *args)
{
# ifdef CONFIG_IA32_EMULATION
	if (task_thread_info(task)->status & TS_COMPAT)
		switch (i) {
		case 0:
			if (!n--) break;
			regs->rbx = *args++;
		case 1:
			if (!n--) break;
			regs->rcx = *args++;
		case 2:
			if (!n--) break;
			regs->rdx = *args++;
		case 3:
			if (!n--) break;
			regs->rsi = *args++;
		case 4:
			if (!n--) break;
			regs->rdi = *args++;
		case 5:
			if (!n--) break;
			regs->rbp = *args++;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
	else
# endif
		switch (i) {
		case 0:
			if (!n--) break;
			regs->rdi = *args++;
		case 1:
			if (!n--) break;
			regs->rsi = *args++;
		case 2:
			if (!n--) break;
			regs->rdx = *args++;
		case 3:
			if (!n--) break;
			regs->r10 = *args++;
		case 4:
			if (!n--) break;
			regs->r8 = *args++;
		case 5:
			if (!n--) break;
			regs->r9 = *args++;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
}

#endif	/* CONFIG_X86_32 */

#endif	/* _ASM_X86_SYSCALL_H */
