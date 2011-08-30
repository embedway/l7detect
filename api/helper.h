#ifndef __HELPER_H__
#define __HELPER_H__

#define align(x, a) (((x) + (a) - 1) & ~((a) - 1))

/**                                                                                                                         
 *@brief 交换a,b的值
*/
#define swap(a, b) \
    do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#ifndef offsetof
#define offsetof(type, member) ( (int) & ((type*)0) -> member )
#endif

#define container_of(ptr, type, member) ({                      \
            const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
            (type *)( (char *)__mptr - offsetof(type,member) );})

enum format_print_type {
    FORMAT_PRINT_WITH_HEAD,
    FORMAT_PRINT_SIMPLE,
};

void list_format_print_head(int width);
void list_format_print_body(void *list, int width, int length, int index, int type);
void list_format_print_buffer(void *list, int width, int length, int type);

#endif
