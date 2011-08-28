#ifndef __HELPER_H__
#define __HELPER_H__

#define align(x, a) (((x) + (a) - 1) & ~((a) - 1))

enum format_print_type {
    FORMAT_PRINT_WITH_HEAD,
    FORMAT_PRINT_SIMPLE,
};

void list_format_print_head(int width);
void list_format_print_body(void *list, int width, int length, int index, int type);
void list_format_print_buffer(void *list, int width, int length, int type);

#endif
