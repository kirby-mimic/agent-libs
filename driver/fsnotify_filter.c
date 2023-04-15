#include <linux/kprobes.h>
#include <asm/current.h>
#include <linux/printk.h>
#include <linux/version.h>

#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
#define _COMPAT_REG (ctx->si)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#define _COMPAT_REG (ctx->dx)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
#define _COMPAT_REG (ctx->r8)
#endif
#endif

#ifdef CONFIG_ARM64
#define _COMPAT_REG (ctx->regs[1])
#endif

#ifndef _COMPAT_REG

void attach_fsnotify_filters(void)
{
	pr_info("attach_fsnotify_filters(): fsnotify filtering is not supported on this architecture")
}

void detach_fsnotify_filters(void)
{
	pr_info("detach_fsnotify_filters(): fsnotify filtering is not supported on this architecture")
}

#else
static int __kprobes fan_filter(struct kprobe *p, struct pt_regs *ctx)
{
	if(ctx && current && !current->in_execve && (_COMPAT_REG & 0x10000))
	{
		_COMPAT_REG &= (~(0x10000));
	}
	return 0;
}

static struct kprobe kp = {
	.symbol_name = "fanotify_handle_event",
	.offset = 0x0,
	.pre_handler = fan_filter,
};

static bool registered = false;
void attach_fsnotify_filters(void)
{
	int ret = register_kprobe(&kp);
	if(ret < 0)
	{
		pr_info("failed to attach fsnotify filters, err=%d", ret);
		return;
	}

	registered = true;
	pr_info("registered fsnotify filter");
}

void detach_fsnotify_filters(void)
{
	if(!registered)
	{
		return;
	}

	unregister_kprobe(&kp);
	pr_info("deregistered fsnotify filter");

	registered = false;
}

#endif
