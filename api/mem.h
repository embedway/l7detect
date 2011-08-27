#include <pthread.h>

#include "common.h"
#include "list.h"

typedef struct zone {
	pthread_mutex_t lock;
	void *baseptr;
	char *name;
	void *freelist;
	uint32_t num_elem;
	uint32_t elem_size;
	uint32_t elem_free;
} zone_t;

zone_t *zone_init(char *name, int32_t element_size, int32_t num_element);
void *zone_alloc(zone_t *mem, uint32_t flags);
void zone_free(zone_t *mem, void *ptr);
int32_t zone_fini(zone_t *mem);

