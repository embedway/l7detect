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

void list_format_print_head(int width) 
{									
	unsigned char head_b[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}; 
	unsigned short head_w[] = {0, 1, 2, 3, 4, 5, 6, 7}; 
	if (width == 8){											
		list_format_print_body(head_b, width, sizeof(head_b), -1, 0);			
	} else {													
		list_format_print_body(head_w, width, sizeof(head_w), -1, 0);			
	}															
}

void list_format_print_body(void *list, int width, int length, int index, int type)
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
				log_print(syslog_p,"%04x: ", index & ~(line_count-1));
			else if (type != FORMAT_PRINT_SIMPLE) 
				log_print(syslog_p,"     ");
		}
		if (width == 8){
			if (index >= 0)
				log_print(syslog_p,"%02x ", list_b[i]);
			else
				log_print(syslog_p,"%2x ", list_b[i]);
		} else {
			if (index >= 0)
				log_print(syslog_p,"%04x ", list_w[i]);
			else
				log_print(syslog_p,"%4x ", list_w[i]);
		}
		if (index >= 0)
			index++;
		if (((i+1) % line_count == 0)) {
			if (index >= 0 && width == 8){
				log_print(syslog_p,"   ");
				for ( j=i-line_count+1; j<=i; j++) {
					if (__is_visible(list_b[j])) {
						log_print(syslog_p,"%c", list_b[j]);
					}else {
						log_print(syslog_p,".");
					}
				}
				char_last = j;
			}
			log_print(syslog_p,"\n");
		}
	}
	
	if (((length_old % 2) != 0) && (width == 16)) {
		unsigned char *p = (unsigned char *)((void *)list + length_old - 1);
		log_print(syslog_p,"%04x ", (*p) << 8);
	}

	if ((index >= 0) && (width == 8) && (j < i)) {
		for (j=i+1; j<=align(i, line_count); j++) {
			log_print(syslog_p,"   ");
		}
		log_print(syslog_p,"   ");
		for (j=char_last; j<i; j++) {
			if (__is_visible(list_b[j])) {
				log_print(syslog_p,"%c", list_b[j]);
			}else {
				log_print(syslog_p,".");
			}
		}
	}
}

void list_format_print_buffer(void *list, int width, int length, int type)
{
	if (type == FORMAT_PRINT_WITH_HEAD)
		list_format_print_head(width);
	list_format_print_body(list, width, length, 0, type);
}
