/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include <string>
#include <stdint.h>

class sinsp_threadinfo;

#include "cgroup_limits.h"
#include "container_engine/container_engine_base.h"
#include "container_engine/sinsp_container_type.h"
#include "container_info.h"
#include "container_async_source.h"
#include <cri.h>

namespace libsinsp {
namespace container_engine {

/**
 * Asynchronous metadata lookup for CRI containers
 *
 * There are two related reasons for asynchronous lookup:
 * 1. Not blocking the main event processing thread
 *
 * 2. Apparently CRI can fail to find a freshly created container
 * for a short while, so we should delay the query a bit.
 */
class cri_async_source : public container_async_source<libsinsp::cgroup_limits::cgroup_limits_key>
{
	using key_type = libsinsp::cgroup_limits::cgroup_limits_key;
public:
	explicit cri_async_source(container_cache_interface* cache, ::libsinsp::cri::cri_interface_v1alpha2* cri,
				  uint64_t ttl_ms):
		container_async_source(NO_WAIT_LOOKUP, ttl_ms, cache),
		m_cri_v1alpha2(cri)
	{
	}

	void quiesce() {
		async_key_value_source::stop();
	}

	bool parse(const key_type& key, sinsp_container_info& container) override;
private:
	const char* name() const override { return "cri"; };

	sinsp_container_type container_type(const key_type& key) const override
	{
		return m_cri_v1alpha2->get_cri_runtime_type();
	}
	std::string container_id(const key_type& key) const override
	{
		return key.m_container_id;
	}

	::libsinsp::cri::cri_interface_v1alpha2* m_cri_v1alpha2;
};

class cri : public container_engine_base
{
public:
	cri(container_cache_interface &cache);
	bool resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info) override;
	void update_with_size(const std::string& container_id) override;
	void cleanup() override;
	static void set_cri_socket_path(const std::string& path);
	static void add_cri_socket_path(const std::string& path);
	static void set_cri_timeout(int64_t timeout_ms);
	static void set_extra_queries(bool extra_queries);
	static void set_async(bool async_limits);

private:
	std::unique_ptr<cri_async_source> m_async_source;
	std::unique_ptr<::libsinsp::cri::cri_interface_v1alpha2> m_cri_v1alpha2;
};
}
}
