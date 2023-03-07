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
#include "podman.h"

#include "container_engine/docker/lookup_request.h"
#include "procfs_utils.h"
#include "runc.h"
#include "sinsp.h"

#include <glob.h>
#include <unistd.h>

#include <fstream>

using namespace libsinsp::container_engine;
using namespace libsinsp::runc;

std::string podman::m_api_sock = "/run/podman/podman.sock";
std::string podman::m_user_api_sock_pattern = "/run/user/*/podman/podman.sock";

namespace {
constexpr const cgroup_layout ROOT_PODMAN_CGROUP_LAYOUT[] = {
	{"/libpod-", ".scope"}, // podman
	{nullptr,    nullptr}
};

std::string get_systemd_cgroup(const sinsp_threadinfo *tinfo)
{
	// the kernel driver does not return cgroups without subsystems (e.g. name=systemd)
	// in the cgroups field, so we have to do a check here, and load /proc/pid/cgroups
	// ourselves if needed

	for(const auto& it : tinfo->cgroups())
	{
		if(it.first == "name=systemd")
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "podman: found systemd cgroup in tinfo");
			return it.second;
		}
	}

	std::stringstream cgroups_file;
	cgroups_file << scap_get_host_root() << "/proc/" << tinfo->m_tid << "/cgroup";

	std::ifstream cgroups(cgroups_file.str());
	return libsinsp::procfs_utils::get_systemd_cgroup(cgroups);
}

int get_userns_root_uid(const sinsp_threadinfo *tinfo)
{
	std::stringstream uid_map_file;
	uid_map_file << scap_get_host_root() << "/proc/" << tinfo->m_tid << "/uid_map";

	std::ifstream uid_map(uid_map_file.str());
	return libsinsp::procfs_utils::get_userns_root_uid(uid_map);
}

// Check whether `tinfo` belongs to a podman container
//
// Returns the uid of the container owner:
//  0 for root containers,
//  >0 for rootless containers,
//  NO_MATCH if the process is not in a podman container
int detect_podman(const sinsp_threadinfo *tinfo, std::string& container_id)
{
	std::string cgroup;
	if(matches_runc_cgroups(tinfo, ROOT_PODMAN_CGROUP_LAYOUT, container_id, cgroup))
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "podman (%s): found ROOT_PODMAN_CGROUP_LAYOUT in %s", container_id.c_str(), cgroup.c_str());

		// User: /user.slice/user-1000.slice/user@1000.service/user.slice/libpod-$ID.scope/container
		// Root: /machine.slice/libpod-$ID.scope/container
		int uid;
		if (sscanf(cgroup.c_str(), "/user.slice/user-%d.slice/", &uid) == 1)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "podman (%s): found user %d", container_id.c_str(), uid);
			return uid;
		}
		g_logger.format(sinsp_logger::SEV_DEBUG, "podman (%s): found root user", container_id.c_str());
		return 0; // root
	}

	std::string systemd_cgroup = get_systemd_cgroup(tinfo);
	if(systemd_cgroup.empty())
	{
		// can't get the cgroup name
		g_logger.format(sinsp_logger::SEV_DEBUG, "podman: did not find systemd cgroup for tid %ld", tinfo->m_tid);
		return libsinsp::procfs_utils::NO_MATCH;
	}

	g_logger.format(sinsp_logger::SEV_DEBUG, "podman: found systemd cgroup %s for tid %ld", systemd_cgroup.c_str(), tinfo->m_tid);

	size_t pos = systemd_cgroup.find("podman-");
	if(pos != std::string::npos)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "podman: found podman- in %s", systemd_cgroup.c_str());
		// .../podman-<pid>.scope/<container_id>
		int podman_pid; // unused except to set the sscanf return value
		char c;         // ^ same
		if(sscanf(systemd_cgroup.c_str() + pos, "podman-%d.scope/%c", &podman_pid, &c) != 2)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "podman: did not find podman.scope/container_id");
			// cgroup doesn't match the expected pattern
			return libsinsp::procfs_utils::NO_MATCH;
		}

		if(!match_one_container_id(systemd_cgroup, ".scope/", "", container_id))
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "podman: could not parse container after podman.scope");
			return libsinsp::procfs_utils::NO_MATCH;
		}

		int uid = get_userns_root_uid(tinfo);
		if(uid == 0)
		{
			// root doesn't spawn rootless containers
			g_logger.format(sinsp_logger::SEV_DEBUG, "podman: detected root user for rootless container");
			return libsinsp::procfs_utils::NO_MATCH;
		}

		return uid;
	}
	else
	{
		// when rootless podman containers are run as a service,
		// there's nothing identifying podman in the cgroup as it looks like:
		// /user.slice/user-<uid>.slice/user@<uid>.service/<unit>/<container_id>
		// where <unit> is whatever started the container, e.g. foo.service
		//
		// let's hope for the best and assume that all such cgroups are
		// podman containers

		// we can probably narrow the prefix down to ".service/" in the typical
		// case but as we're already basically guessing, let's keep it generic
		if(!match_one_container_id(systemd_cgroup, "/", "", container_id))
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "podman: could not parse container after slash");
			return libsinsp::procfs_utils::NO_MATCH;
		}

		int uid;
		if (sscanf(systemd_cgroup.c_str(), "/user.slice/user-%d.slice/", &uid) == 1)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "podman: found user slice for uid %d", uid);
			return uid;
		}
		g_logger.format(sinsp_logger::SEV_DEBUG, "podman: could not parse user from slice");
		return libsinsp::procfs_utils::NO_MATCH;
	}
}
}

bool podman::can_api_sock_exist()
{
	glob_t gl;
	int rc;
	int glob_flags = 0;

	// If the GNU extension GLOB_BRACE were universal, we could
	// probably do this as one glob.

	if (access(m_api_sock.c_str(), R_OK|W_OK) == 0)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "podman: found root socket");
		return true;
	}

	// NULL is errfunc
	rc = glob(m_user_api_sock_pattern.c_str(), glob_flags, NULL, &gl);
	globfree(&gl);

	g_logger.format(sinsp_logger::SEV_DEBUG, "podman: %s socket", rc == 0 ? "found user" : "did not find any");

	return (rc == 0);
}

bool podman::resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info)
{
	std::string container_id, api_sock;

	if(m_api_sock_can_exist == nullptr)
	{
		m_api_sock_can_exist.reset(new bool(can_api_sock_exist()));
	}

	if(! (*(m_api_sock_can_exist.get())))
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "podman: not detected");
		return false;
	}

	int uid = detect_podman(tinfo, container_id);

	switch(uid)
	{
	case 0: // root, use the default socket
		api_sock = m_api_sock;
		break;
	case libsinsp::procfs_utils::NO_MATCH:
		return false;
	default: // rootless container, use the user's socket
		api_sock = "/run/user/" + std::to_string(uid) + "/podman/podman.sock";
		break;
	}

	g_logger.format(sinsp_logger::SEV_DEBUG, "podman (%s): using %s", container_id.c_str(), api_sock.c_str());

	docker_lookup_request request(container_id, api_sock, CT_PODMAN, uid, false);
	return resolve_impl(tinfo, request, query_os_for_missing_info);
}
