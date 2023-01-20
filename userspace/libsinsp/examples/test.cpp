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

#include <cstdlib>
#include <iostream>
#ifndef WIN32
#include <getopt.h>
#endif
#include <csignal>
#include <sinsp.h>
#include <functional>
#include <memory>
#include "util.h"

#ifndef WIN32
extern "C" {
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
}
#endif

using namespace std;

// Functions used for dumping to stdout
void plaintext_dump(sinsp_evt* ev);
void formatted_dump(sinsp_evt* ev);

std::function<void(sinsp_evt*)> dump;
static bool g_interrupted = false;
static const uint8_t g_backoff_timeout_secs = 2;
static bool g_all_threads = false;
string engine_string = KMOD_ENGINE; /* Default for backward compatibility. */
string filter_string = "";
string file_path = "";
string bpf_path = "";
unsigned long buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM;

sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error);

#define PROCESS_DEFAULTS "*%evt.num %evt.time %evt.category %container.id %proc.ppid %proc.pid %evt.type %proc.exe %proc.cmdline %evt.args"

std::string default_output = DEFAULT_OUTPUT_STR;
std::string process_output = PROCESS_DEFAULTS;

static std::unique_ptr<sinsp_evt_formatter> default_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> process_formatter = nullptr;

static void sigint_handler(int signum)
{
	g_interrupted = true;
}

static void usage()
{
	string usage = R"(Usage: sinsp-example [options]

Overview: Goal of sinsp-example binary is to test and debug sinsp functionality and print events to STDOUT. All drivers are supported.

Options:
  -h, --help                                 Print this page.
  -f <filter>, --filter <filter>             Filter string for events (see https://falco.org/docs/rules/supported-fields/ for supported fields).
  -j, --json                                 Use JSON as the output format.
  -a, --all-threads                          Output information about all threads, not just the main one.
  -b <path>, --bpf <path>                    BPF probe.
  -m, --modern_bpf                           modern BPF probe.
  -k, --kmod                                 Kernel module
  -s <path>, --scap_file <path>              Scap file
  -d <dim>, --buffer_dim <dim>               Dimension in bytes that every per-CPU buffer will have.
  -o <fields>, --output-fields <fields>      Output fields string (see <filter> for supported display fields) that overwrites default output fields for all events. * at the beginning prints JSON keys with null values, else no null fields are printed.
)";
	cout << usage << endl;
}

#ifndef WIN32
// Parse CLI options.
void parse_CLI_options(sinsp& inspector, int argc, char** argv)
{
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"filter", required_argument, 0, 'f'},
		{"json", no_argument, 0, 'j'},
		{"all-threads", no_argument, 0, 'a'},
		{"bpf", required_argument, 0, 'b'},
		{"modern_bpf", no_argument, 0, 'm'},
		{"kmod", no_argument, 0, 'k'},
		{"scap_file", required_argument, 0, 's'},
		{"buffer_dim", required_argument, 0, 'd'},
		{"output-fields", required_argument, 0, 'o'},
		{0, 0, 0, 0}};

	int op;
	int long_index = 0;
	while((op = getopt_long(argc, argv,
				"hf:jae:b:d:s:o:",
				long_options, &long_index)) != -1)
	{
		switch(op)
		{
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case 'f':
			filter_string = optarg;
			break;
		case 'j':
			inspector.set_buffer_format(sinsp_evt::PF_JSON);
			break;
		case 'a':
			g_all_threads = true;
			break;
		case 'b':
			engine_string = BPF_ENGINE;
			bpf_path = optarg;
			break;
		case 'm':
			engine_string = MODERN_BPF_ENGINE;
			break;
		case 'k':
			engine_string = KMOD_ENGINE;
			break;
		case 's':
			engine_string = SAVEFILE_ENGINE;
			file_path = optarg;
			break;
		case 'd':
			buffer_bytes_dim = strtoul(optarg, NULL, 10);
			break;
		case 'o':
			default_output = optarg;
			process_output = optarg;
			break;
		default:
			break;
		}
	}
}
#endif /* WIN32 */

void open_engine(sinsp& inspector)
{
	std::cout << "-- Try to open: '" + engine_string + "' engine." << std::endl;

	/* Get only necessary tracepoints. */
	std::unordered_set<uint32_t> tp_set = inspector.enforce_sinsp_state_tp();
	std::unordered_set<uint32_t> ppm_sc;

	if(!engine_string.compare(KMOD_ENGINE))
	{
		inspector.open_kmod(buffer_bytes_dim, ppm_sc, tp_set);
	}
	else if(!engine_string.compare(BPF_ENGINE))
	{
		if(bpf_path.empty())
		{
			std::cerr << "You must specify the path to the bpf probe if you use the 'bpf' engine" << std::endl;
			exit(EXIT_FAILURE);
		}
		else
		{
			std::cerr << bpf_path << std::endl;
		}
		inspector.open_bpf(bpf_path.c_str(), buffer_bytes_dim, ppm_sc, tp_set);
	}
	else if(!engine_string.compare(SAVEFILE_ENGINE))
	{
		if(file_path.empty())
		{
			std::cerr << "You must specify the path to the file if you use the 'savefile' engine" << std::endl;
			exit(EXIT_FAILURE);
		}
		inspector.open_savefile(file_path.c_str(), 0);
	}
	else if(!engine_string.compare(MODERN_BPF_ENGINE))
	{
		inspector.open_modern_bpf(buffer_bytes_dim, ppm_sc, tp_set);
	}
	else
	{
		std::cerr << "Unknown engine" << std::endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "-- Engine '" + engine_string + "' correctly opened." << std::endl;
}

#ifdef __linux__
#define insmod(fd, opts, flags) syscall(__NR_finit_module, fd, opts, flags)
#define rmmod(name, flags) syscall(__NR_delete_module, name, flags)

static void remove_module()
{
	if (rmmod("scap", 0) != 0)
	{
		cerr << "[ERROR] Failed to remove kernel module" << strerror(errno) << endl;
	}
}

static bool insert_module()
{
	// Check if we are configured to run with the kernel module
	if(engine_string.compare(KMOD_ENGINE))
		return true;

	char *driver_path = getenv("KERNEL_MODULE");
	if (driver_path == NULL || *driver_path == '\0')
	{
		// We don't have a path set, assuming the kernel module is already there
		return true;
	}

	int res;
	int fd = open(driver_path, O_RDONLY);
	if (fd < 0)
		goto error;

	res = insmod(fd, "", 0);
	if (res != 0)
		goto error;

	atexit(remove_module);

	return true;

error:
	cerr << "[ERROR] Failed to insert kernel module: " << strerror(errno) << endl;

	if (fd > 0)
	{
		close(fd);
	}

	return false;
}
#endif

//
// Sample filters:
//   "evt.category=process or evt.category=net"
//   "evt.dir=< and (evt.category=net or (evt.type=execveat or evt.type=execve or evt.type=clone or evt.type=fork or evt.type=vfork))"
//
int main(int argc, char** argv)
{
	sinsp inspector;
	dump = plaintext_dump;

#ifndef WIN32
	parse_CLI_options(inspector, argc, argv);

#ifdef __linux__
	// Try inserting the kernel module
	bool res = insert_module();
	if (!res)
	{
		return -1;
	}
#endif

	signal(SIGPIPE, sigint_handler);
#endif

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	open_engine(inspector);

	std::cout << "-- Start capture" << std::endl;

	if(!filter_string.empty())
	{
		try
		{
			inspector.set_filter(filter_string);
		}
		catch(const sinsp_exception& e)
		{
			cerr << "[ERROR] Unable to set filter: " << e.what() << endl;
		}
	}

	default_formatter.reset(new sinsp_evt_formatter(&inspector, default_output));
	process_formatter.reset(new sinsp_evt_formatter(&inspector, process_output));

	while(!g_interrupted)
	{
		sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg)
					  { cout << "[ERROR] " << error_msg << endl; });
		if(ev != nullptr)
		{
			dump(ev);
		}
	}

	return 0;
}

sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error)
{
	sinsp_evt* ev = nullptr;

	int32_t res = inspector.next(&ev);

	if(res == SCAP_SUCCESS)
	{
		return ev;
	}

	if(res != SCAP_TIMEOUT)
	{
		handle_error(inspector.getlasterr());
		std::this_thread::sleep_for(std::chrono::seconds(g_backoff_timeout_secs));
	}

	return nullptr;
}

void plaintext_dump(sinsp_evt* ev)
{
	sinsp_threadinfo* thread = ev->get_thread_info();
	if(thread)
	{
		string cmdline;
		sinsp_threadinfo::populate_cmdline(cmdline, thread);

		if(!g_all_threads && !thread->is_main_thread())
		{
			return;
		}

		bool is_host_proc = thread->m_container_id.empty();
		cout << '[' << (is_host_proc ? "HOST" : thread->m_container_id) << "]:";

		cout << "[CAT=";

		if(ev->get_category() == EC_PROCESS)
		{
			cout << "PROCESS]:";
		}
		else if(ev->get_category() == EC_NET)
		{
			cout << get_event_category_name(ev->get_category()) << ":";
			sinsp_fdinfo_t* fd_info = ev->get_fd_info();

			// event subcategory should contain SC_NET if ipv4/ipv6
			if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
			{
				cout << fd_info->tostring() << "]:";
			}
		}
		else if(ev->get_category() == EC_IO_READ || ev->get_category() == EC_IO_WRITE)
		{
			cout << get_event_category_name(ev->get_category()) << ":";

			sinsp_fdinfo_t* fd_info = ev->get_fd_info();
			if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
			{
				cout << fd_info->tostring() << "]:";
			}
		}
		else
		{
			cout << get_event_category_name(ev->get_category()) << "]:";
		}
	}
	else
	{
		cout << "[EVENT]:[" << get_event_category_name(ev->get_category()) << "]:";
	}

	formatted_dump(ev);
}


void formatted_dump(sinsp_evt* ev)
{
	std::string output;
	sinsp_threadinfo* thread = ev->get_thread_info();

	if(thread)
	{
		if(g_all_threads || thread->is_main_thread())
		{
			if(ev->get_category() == EC_PROCESS)
			{
				process_formatter->tostring(ev, output);
			}
			else
			{
				default_formatter->tostring(ev, output);
			}
		}
		else
		{
			// Prevent empty lines from being printed
			return;
		}
	}
	else
	{
		default_formatter->tostring(ev, output);
	}

	cout << output << std::endl;
}
