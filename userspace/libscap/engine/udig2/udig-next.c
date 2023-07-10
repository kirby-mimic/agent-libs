#include "udig-int.h"
#include "scap.h"
#include "ringbuffer/devset.h"
#include "ringbuffer/ringbuffer.h"

#include <fcntl.h>

static inline bool should_close_device(struct scap_device *dev, struct timespec *now)
{
	printf("[CHICKEN] %s | %d | Should I close device m_fd %d?\n", __FUNCTION__, __LINE__, dev->m_fd);
	if(dev->m_bufinfo->head != dev->m_bufinfo->tail)
	{
		// still has unconsumed events
		printf("[CHICKEN] %s | %d | Nop, could not close m_fd %d due to uncosumed events\n", __FUNCTION__, __LINE__, dev->m_fd);
		return false;
	}

	struct timespec last_event = dev->m_bufstatus->m_last_event_time;

	if(now->tv_sec - last_event.tv_sec > 5) // over 5 seconds since last event?
	{
		struct flock lock = {
			.l_type = F_WRLCK,
			.l_start = 1,
			.l_len = 1,
			.l_whence = 0,
		};

		int res = fcntl(dev->m_fd, F_GETLK, &lock);

		if(res == 0 && lock.l_type == F_UNLCK)
		{
			printf("[CHICKEN] %s | %d | Yes, device m_fd %d should be closed\n", __FUNCTION__, __LINE__, dev->m_fd);
			return true;
		}
		dev->m_bufstatus->m_last_event_time = *now;
	}

	printf("[CHICKEN] %s | %d | Nop, I won't close device m_fd %d\n", __FUNCTION__, __LINE__, dev->m_fd);
	return false;
}

__attribute__((flatten)) int32_t scap_udig_next(struct scap_engine_handle engine, scap_evt **pevent, uint16_t *pcpuid)
{

	struct scap_udig *handle = engine.m_handle;
	int32_t res = ringbuffer_next(&handle->m_dev_set, pevent, pcpuid);

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	if(*pcpuid != 65535)
	{
		printf("[CHICKEN] %s | %d | *pcpuid != 65535\n", __FUNCTION__, __LINE__);
		struct scap_device *dev = &handle->m_dev_set.m_devs[*pcpuid];
		dev->m_bufstatus->m_last_event_time = now;
	}


	for(int i = 0; i < handle->m_dev_set.m_ndevs; ++i)
	{

		struct scap_device *dev = &handle->m_dev_set.m_devs[i];
		if(dev->m_state != DEV_OPEN)
		{
			continue;
		} else {
			printf("[CHICKEN] %s | %d | device m_fd %d num %d OPEN\n", __FUNCTION__, __LINE__, dev->m_fd, i);
		}

		if(should_close_device(dev, &now))
		{
			scap_udig_close_dev(dev, &handle->m_dev_set.old_stats);
			printf("[CHICKEN] %s | %d | Should CLOSE device m_fd %d num %d OPEN\n", __FUNCTION__, __LINE__, dev->m_fd, i);
			ASSERT(handle->m_dev_set.m_used_devs > 0);
			handle->m_dev_set.m_used_devs--;
		}
	}

	if(handle->m_dev_set.m_used_devs == handle->m_dev_set.m_alloc_devs)
	{
		printf("[CHICKEN] %s | %d | Devset grow, used devs %d\n", __FUNCTION__, __LINE__, handle->m_dev_set.m_used_devs);
		devset_grow(&handle->m_dev_set, handle->m_dev_set.m_alloc_devs * 2, handle->m_lasterr);
	}

	return res;
}
