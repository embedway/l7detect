#include <string.h>
#include "common.h"
#include "log.h"
#include "helper.h"

static inline int __is_visible(unsigned char value)
{
	if ((value > 0x20) && (value < 0x80))
		return 1;
	else
		return 0;
}

void list_format_print_head(log_t *log_p, int width) 
{									
	unsigned char head_b[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}; 
	unsigned short head_w[] = {0, 1, 2, 3, 4, 5, 6, 7}; 
	if (width == 8){											
		list_format_print_body(log_p, head_b, width, sizeof(head_b), -1, 0);			
	} else {													
		list_format_print_body(log_p, head_w, width, sizeof(head_w), -1, 0);			
	}															
}

void list_format_print_body(log_t *log_p, void *list, int width, int length, int index, int type)
{
	int i, j, char_last;
 	unsigned char *list_b = (unsigned char *)list;
	unsigned short *list_w = (unsigned short *)list;
	int length_old = length;

    if (width != 8 && width != 16) {
        width = 8;
    }

	if (width == 16) {
		length = length/2;
	}

	int line_count = 128/width;
	
	j = char_last = 0;

	for (i=0; i<length; i++){
		if (i%line_count == 0) {
			if ((index >= 0) && (type == FORMAT_PRINT_WITH_HEAD))
				log_print(log_p,"%04x: ", index & ~(line_count-1));
			else if (type != FORMAT_PRINT_SIMPLE) 
				log_print(log_p,"     ");
		}
		if (width == 8){
			if (index >= 0)
				log_print(log_p,"%02x ", list_b[i]);
			else
				log_print(log_p,"%2x ", list_b[i]);
		} else {
			if (index >= 0)
				log_print(log_p,"%04x ", list_w[i]);
			else
				log_print(log_p,"%4x ", list_w[i]);
		}
		if (index >= 0)
			index++;
		if (((i+1) % line_count == 0)) {
			if (index >= 0 && width == 8){
				log_print(log_p,"   ");
				for ( j=i-line_count+1; j<=i; j++) {
					if (__is_visible(list_b[j])) {
						log_print(log_p,"%c", list_b[j]);
					}else {
						log_print(log_p,".");
					}
				}
				char_last = j;
			}
			log_print(log_p,"\n");
		}
	}
	
	if (((length_old % 2) != 0) && (width == 16)) {
		unsigned char *p = (unsigned char *)((void *)list + length_old - 1);
		log_print(log_p,"%04x ", (*p) << 8);
	}

	if ((index >= 0) && (width == 8) && (j < i)) {
		for (j=i+1; j<=align(i, line_count); j++) {
			log_print(log_p,"   ");
		}
		log_print(log_p,"   ");
		for (j=char_last; j<i; j++) {
			if (__is_visible(list_b[j])) {
				log_print(log_p,"%c", list_b[j]);
			}else {
				log_print(log_p,".");
			}
		}
	}
}

void list_format_print_buffer(log_t *log_p, void *list, int width, int length, int type)
{
	if (type == FORMAT_PRINT_WITH_HEAD)
		list_format_print_head(log_p, width);
	list_format_print_body(log_p, list, width, length, 0, type);
}

int kv_get_index_from_key(kv_table_t *table, char *key)
{
	int i;
	for (i=0; table[i].key != NULL; i++) {
		if (strncmp(table[i].key, key, strlen(table[i].key)) == 0) {
			return i;
		}
	}
	return -1;
}

int kv_get_index_from_value(kv_table_t *table, int value)
{
	int i;
	for (i=0; table[i].key != NULL; i++) {
		if (table[i].value == value) {
			return i;
		}
	}
	return -1;
}
