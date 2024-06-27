//Features first
#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define ENABLE_IDENTITY_MARK 1
#define ENABLE_NODEPORT 1
#define ENABLE_CLUSTER_AWARE_ADDRESSING 1
#define ENABLE_INTER_CLUSTER_SNAT 1
#define ENABLE_HIGH_SCALE_IPCACHE 1
#define ENABLE_MASQUERADE 1
#define ENABLE_MASQUERADE_IPV4 1
#define ENABLE_MASQUERADE_IPV6 1
#define ENABLE_HOST_FIREWALL 1
#define ENABLE_NAT_46X64 1
#define ENABLE_SRC_RANGE_CHECK 1
#define ENABLE_WIREGUARD 1
#define ENABLE_VTEP 1

#include "tc_user.h"
#include "../lib/nat.h"
#include "endian.h"
#include <string.h>
#include <stdint.h>
#include <assert.h>

#define MIN_PORT 5000

void fill_in_map(void* map, int perc_occupancy)
{
	//TODO XXX
}

int test_snat_port_alloc(bool v4, uint16_t n_ports, int perc_occupancy,
							uint64_t iterations)
{
	struct __sk_buff ctx;
	void *map = v4? (void*)&CT_MAP_TCP4 : (void*)&CT_MAP_TCP6;
	__s8 err;

	struct ipv4_ct_tuple tuple4 = {
		.daddr = htobe32(0x0A000001),
		.saddr = htobe32(0x0A000002),
		.dport = htobe16(80),
		.sport = htobe16(5001)
	};
	struct ipv4_nat_entry ostate = {0};

	struct ipv4_nat_target target = {
		.addr = 0x01020304,
		.min_port = MIN_PORT,
		.max_port =  MIN_PORT + n_ports,
		.from_local_endpoint = false,
		.egress_gateway = false,
		.cluster_id = 1,
		.needs_ct = false
	};

	//Prefill up to occuppancyprefill map
	fill_in_map(map, perc_occupancy);
	test_init_msg("'%s:v%d'\n", __FUNCTION__, v4? 4 : 6);

	uint64_t failed_iterations = 0ULL;
	if (v4) {
		for(uint64_t i = 0; i < iterations; ++i) {
			if (snat_v4_new_mapping(&ctx, map, &tuple4, &ostate,
							&target, false, &err))
				++failed_iterations;
		}
	} else {
		//TODO XXX
	}

	test_assert(success_100, failed_iterations == 0);
	mock_map_clear(map);

	test_result_msg("'%s:v%d'\n", __FUNCTION__, v4? 4 : 6);

	return test_result();
}

int main(int args, char** argv)
{
	int rc = 0;

	mock_init();

	//20K ports, 50 occupancy, 100K iterations
	rc |= test_snat_port_alloc(true, 20000, 50, 100000);

	mock_fini();

	return rc;
}
