#include <stdlib.h>
#include <assert.h>

#include "common.h"
#include "log.h"
#include "mem.h"

zone_t *zone_init(char *name, int32_t elem_size, int32_t num_elem)
{
	void *ptr;
	zone_t *zone;
	int status, i;

	ptr = malloc(sizeof(zone_t) + elem_size * num_elem);
	if_error_return(ptr != NULL, NULL);
	
	zone = (zone_t *)(ptr + elem_size * num_elem);
	zone->elem_size = elem_size;
    zone->num_elem = num_elem;
    zone->name = name;
	zone->baseptr = NULL;
    zone->freelist = NULL;

	status = pthread_mutex_init(&zone->lock, NULL);
	if (status != 0) {
		free(ptr);
		return NULL;
	}
	zone->baseptr = (char *)ptr;
	for(i=0; i<num_elem; i++)
    {
        *(void **)(zone->baseptr + (i*elem_size)) = zone->freelist;
        zone->freelist = (void *)(zone->baseptr + (i*elem_size));
    }
	zone->elem_free = num_elem;
	return zone;
}

void * zone_alloc(zone_t *zone, uint32_t flags)
{
    zone_t *item;

    assert(zone != NULL);
    assert(zone->baseptr != NULL);
    pthread_mutex_lock(&zone->lock);

	item = (zone_t *)zone->freelist;
	if(item != NULL)
	{
		zone->freelist = *(void **)item;
		zone->elem_free--;
	} else {
		/*做些什么呢？*/
		
	}
    pthread_mutex_unlock(&zone->lock);
    return(item);
}

void zone_free(zone_t *zone, void *ptr)
{
    assert(zone != NULL);
    assert(zone->baseptr != NULL);
    assert((unsigned long)ptr - (unsigned long)zone->baseptr < zone->num_elem * zone->elem_size);

    pthread_mutex_lock(&zone->lock);
	*(void **)ptr = zone->freelist;
	zone->freelist = ptr;
	zone->elem_free++;
    pthread_mutex_unlock(&zone->lock);
}

int32_t zone_fini(zone_t *zone)
{
	if (zone != NULL && zone->baseptr != NULL) {
		free(zone->baseptr);
	}
	return 0;
}

