#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <assert.h>

#define __BPF_STDDEF_H_ 1
#define __DONT_INCLUDE_MAPS__ 1
#include <linux/bpf.h>
#include "map.h"

#define MAX_KEY_VAL_SIZE 2048
#define DEFAULT_MAX_ENTRIES 65535

typedef struct {
	__u8 bytes[MAX_KEY_VAL_SIZE];
} __attribute__((packed)) key_val_t;

//std::map compare op
inline bool operator<(const key_val_t& a1, const key_val_t& a2)
{
	return memcmp((const void*)&a1, (const void*)&a2,
						sizeof(key_val_t)) < 0;
}

typedef struct bpf_uspace_map_int {
	union bpf_attr m;
	__u32 n_entries;
	std::map<key_val_t, key_val_t>* ptr;
} bpf_uspace_map_int_t;

//Holds the instances of ALL maps
static std::map<const void*, bpf_uspace_map_int_t*>* maps = NULL;

static bpf_uspace_map_int_t* map_int_get(const void* ptr)
{
	auto it = maps->find(ptr);
	if(it == maps->end())
		return NULL;
	return it->second;
}

static bpf_uspace_map_int_t* create_map(__u32 type, __u32 key_size,
							__u32 value_size,
							__u32 max_entries,
							__u32 flags)
{
	bpf_uspace_map_int_t* int_map = new bpf_uspace_map_int_t;
	memset(int_map, 0, sizeof(bpf_uspace_map_int_t));

	//Basics
	int_map->m.map_type = type;
	int_map->m.key_size = key_size;
	int_map->m.value_size = value_size;
	int_map->m.max_entries = max_entries;
	int_map->m.flags = flags;

	//Real map
	switch (type) {
		case BPF_MAP_TYPE_HASH:
		case BPF_MAP_TYPE_LRU_HASH:
			int_map->ptr = new std::map<key_val_t, key_val_t>();
			break;
		default:
			//Not yet supported
			assert(0);
			break;
	}

	return int_map;
}

static void destroy_map(bpf_uspace_map_int_t* map)
{
	delete map->ptr;
	delete map;
}

void mock_maps_init()
{
	//Connection tracking maps
	maps = new std::map<const void*, bpf_uspace_map_int_t*>();
	(*maps)[&CT_MAP_TCP4] = create_map(BPF_MAP_TYPE_LRU_HASH,
						CT_X4_KEY_SIZE,
						CT_XX_VAL_SIZE,
						DEFAULT_MAX_ENTRIES,
						0);
	(*maps)[&CT_MAP_ANY4] = create_map(BPF_MAP_TYPE_LRU_HASH,
						CT_X4_KEY_SIZE,
						CT_XX_VAL_SIZE,
						DEFAULT_MAX_ENTRIES,
						0);
	(*maps)[&CT_MAP_TCP6] = create_map(BPF_MAP_TYPE_LRU_HASH,
						CT_X6_KEY_SIZE,
						CT_XX_VAL_SIZE,
						DEFAULT_MAX_ENTRIES,
						0);
	(*maps)[&CT_MAP_ANY6] = create_map(BPF_MAP_TYPE_LRU_HASH,
						CT_X6_KEY_SIZE,
						CT_XX_VAL_SIZE,
						DEFAULT_MAX_ENTRIES,
						0);
}

void mock_maps_fini()
{
	for (auto it: *maps)
		destroy_map(it.second);
	delete maps;
}

int mock_map_update_elem(const void *map, const void *key,
					const void *value, __u32 flags)
{
	//Recover map
	bpf_uspace_map_int_t* int_map = map_int_get(map);
	if (!int_map)
		return -1;

	key_val_t aux_key = {0};
	key_val_t aux_val;

	memcpy(&aux_key, key, int_map->m.key_size);
	memcpy(&aux_val, value, int_map->m.value_size);

	auto it = int_map->ptr->find(aux_key);
	if (it != int_map->ptr->end()) {
		(*int_map->ptr)[aux_key] = aux_val;
		return 0;
	}

	if (int_map->n_entries >= int_map->m.max_entries) {
		//TODO: LRU eviction
		return -1;
	}

	++int_map->n_entries;
	(*int_map->ptr)[aux_key] = aux_val;

	return 0;
}

void* mock_map_lookup_elem(const void* map, const void *key)
{
	//Recover map
	bpf_uspace_map_int_t* int_map = map_int_get(map);
	if (!int_map)
		return NULL;

	key_val_t aux_key = {0};
	memcpy(&aux_key, key, int_map->m.key_size);

	auto it = int_map->ptr->find(aux_key);
	if (it == int_map->ptr->end())
		return NULL;

	return (void*)&it->second;
}

int mock_map_delete_elem(void* map, const void *key)
{
	//Recover map
	bpf_uspace_map_int_t* int_map = map_int_get(map);
	if (!int_map)
		return -1;

	key_val_t aux_key = {0};
	memcpy(&aux_key, key, int_map->m.key_size);

	auto it = int_map->ptr->find(aux_key);
	if (it == int_map->ptr->end())
		return -1;

	--int_map->n_entries;
	int_map->ptr->erase(it);
	return 0;
}

__u32 mock_map_get_size(void* map)
{
	//Recover map
	bpf_uspace_map_int_t* int_map = map_int_get(map);
	if (!int_map)
		return 0;
	return int_map->ptr->size();
}

int mock_map_clear(void* map)
{
	//Recover map
	bpf_uspace_map_int_t* int_map = map_int_get(map);
	if (!int_map)
		return 1;

	int_map->n_entries = 0;
	int_map->ptr->clear();

	return 0;
}
