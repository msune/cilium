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
#include "../lib/conntrack.h"
#include "endian.h"
#include <string.h>

int test_ct_create(bool v4)
{
	void *map = v4? (void*)&CT_MAP_TCP4 : (void*)&CT_MAP_TCP6;
	void *map_related = NULL;
	struct __sk_buff ctx;
	enum ct_dir dir = CT_INGRESS;
	struct ct_state ct_state; (void)ct_state;
	struct ipv4_ct_tuple tuple4;
	struct ipv6_ct_tuple tuple6;
	void* tuple;
	__s8 err;


	test_init_msg("'%s:v%d'\n", __FUNCTION__, v4? 4 : 6);

	//Connection info
	tuple = v4? (void*)&tuple4 : (void*)&tuple6;
	if (v4) {
		tuple4.saddr = __bpf_htonl(0x0A000001);
		tuple4.daddr = __bpf_htonl(0x0A000201);
	} else {
		struct in6_addr aux;
		aux.s6_addr32[0] = __bpf_htonl(0x2100);
		aux.s6_addr32[1] = 0x0;
		aux.s6_addr32[2] = 0x0;
		aux.s6_addr32[3] = __bpf_htonl(0x1);
		memcpy(&tuple6.saddr, &aux, sizeof(aux));
		aux.s6_addr32[2] = __bpf_htonl(0x2);
		memcpy(&tuple6.daddr, &aux, sizeof(aux));
	}

	//Common
	tuple4.nexthdr = tuple6.nexthdr = IPPROTO_TCP;
	tuple4.sport = tuple6.sport = __bpf_htons(34567);
	tuple4.dport = tuple6.dport = __bpf_htons(80);
	tuple4.flags = tuple6.flags = 0;

	//pkt
	ctx.len = 1500;
	ctx.mark = 0x0;
	ctx.ifindex = 2;

	//Set wall-clock
	mock_set_time(0x100ULL);

	//Create CT state without map related
	if (v4) {
		test_assert_rc(dummy_test, 0, ct_create4(map, map_related,
							tuple, &ctx, dir,
							NULL, &err));
	} else {
		test_assert_rc(dummy_test, 0, ct_create6(map, map_related,
							tuple, &ctx, dir,
							NULL, &err));
	}
	test_assert(map_check_map_tcp_size,  mock_map_get_size(map) == 1);
	struct ct_entry* aux = (struct ct_entry*)map_lookup_elem(map, tuple);
	test_assert(map_check_tuple, aux != NULL);
	test_assert(check_entry_pkts, aux->packets == 1);
	test_assert(check_entry_bytes, aux->bytes == 1500);
	test_assert(check_entry_last_seen, aux->last_rx_report == 0x100ULL);

	//Create a new entry with the same CT state should override
	ctx.len = 1000;
	ctx.mark = 0x0;
	ctx.ifindex = 2;
	mock_set_time(0x200ULL);

	if (v4) {
		test_assert_rc(dummy_test, 0, ct_create4(map, map_related,
							tuple, &ctx, dir,
							NULL, &err));
	} else {
		test_assert_rc(dummy_test, 0, ct_create6(map, map_related,
							tuple, &ctx, dir,
							NULL, &err));
	}
	test_assert(map_check_map_tcp_size2,  mock_map_get_size(map) == 1);
	struct ct_entry* aux2 = (struct ct_entry*)map_lookup_elem(map, tuple);
	test_assert(map_check_tuple2, aux2 != NULL);
	test_assert(map_check_tuple2_2, aux2 == aux);
	test_assert(check_entry_pkts2, aux2->packets == 1);
	test_assert(check_entry_bytes2, aux2->bytes == 1000);
	test_assert(check_entry_last_seen2, aux2->last_rx_report == 0x200ULL);

	//Test map related insertion
	ctx.len = 800;
	ctx.mark = 0x0;
	ctx.ifindex = 1;
	mock_set_time(0x300ULL);

	map_related = v4? (void*)&CT_MAP_ANY4 : (void*)&CT_MAP_ANY6;
	if (v4) {
		test_assert_rc(dummy_test, 0, ct_create4(map, map_related,
							tuple, &ctx, dir,
							NULL, &err));
	} else {
		test_assert_rc(dummy_test, 0, ct_create6(map, map_related,
							tuple, &ctx, dir,
							NULL, &err));
	}
	test_assert(map_check_map_tcp_size3,  mock_map_get_size(map) == 1);
	aux2 = (struct ct_entry*)map_lookup_elem(map, tuple);

	struct ipv4_ct_tuple icmp4_tuple;
	struct ipv6_ct_tuple icmp6_tuple;

	if (v4) {
		icmp4_tuple.saddr = tuple4.saddr;
		icmp4_tuple.daddr = tuple4.daddr;
		icmp4_tuple.nexthdr = IPPROTO_ICMP;
		icmp4_tuple.flags = tuple4.flags | TUPLE_F_RELATED;
	} else {
		memcpy(&icmp6_tuple.saddr, &tuple6.saddr, sizeof(tuple6.saddr));
		memcpy(&icmp6_tuple.daddr, &tuple6.daddr, sizeof(tuple6.daddr));
		icmp6_tuple.nexthdr = IPPROTO_ICMPV6;
		icmp6_tuple.flags = tuple6.flags | TUPLE_F_RELATED;
	}
	icmp4_tuple.sport = icmp6_tuple.sport = 0;
	icmp4_tuple.dport = icmp6_tuple.dport = 0;

	void* icmp_tuple = v4? (void*)&icmp4_tuple : (void*)&icmp6_tuple;

	struct ct_entry* aux3 = (struct ct_entry*)map_lookup_elem(map_related,
								icmp_tuple);
	test_assert(map_check_map_tcp_size3_2,
					mock_map_get_size(map_related) == 1);
	test_assert(map_check_tuple3, aux3 != NULL);
	test_assert(check_entry_pkts3, aux3->packets == 0);
	test_assert(check_entry_bytes3, aux3->bytes == 0);
	test_assert(check_entry_last_seen3, aux3->last_rx_report == 0x300ULL);

	//Cleanup
	mock_map_clear(map);
	mock_map_clear(map_related);

	test_result_msg("'%s:v%d'\n", __FUNCTION__, v4? 4 : 6);

	return test_result();
}


int main(int args, char** argv)
{
	int rc = 0;

	mock_init();

	rc |= test_ct_create(true);
	rc |= test_ct_create(false);

	//TODO add more (lookup)

	mock_fini();

	return rc;
}
