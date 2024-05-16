#include <stdbool.h>
#include <linux/bpf.h>

bool mock_time_inc = false;
__u64 mock_time_now = 0ULL;
