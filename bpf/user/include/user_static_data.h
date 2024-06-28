#ifndef BPF_USPACE_STATIC_DATA_MOCK_H
#define BPF_USPACE_STATIC_DATA_MOCK_H

//Sanity
#ifdef __LIB_STATIC_DATA__
	#error user_static_data.h must be included before any other header!
#endif

#define CONFIG(name) __config_##name 

#endif //BPF_USPACE_STATIC_DATA_MOCK_H
