#ifndef __LOCK_H__
#define __LOCK_H__

enum lock_type {
	SPINLOCK,
	MUTEX,
	RWLOCK,
	LOCK_TYPE_INVALID,
};

#ifdef __linux__

#include <pthread.h>
#define mutex_init pthread_mutex_init
#define mutex_lock pthread_mutex_lock
#define mutex_unlock pthread_mutex_unlock
#define mutex_destory pthread_mutex_destroy
typedef pthread_mutex_t mutex_t;

#define spin_init pthread_spin_init
#define spin_lock pthread_spin_lock
#define spin_unlock pthread_spin_unlock
#define spin_destory pthread_spin_destroy
typedef pthread_spinlock_t spinlock_t;

#define rwlock_init pthread_rwlock_init
#define rwlock_rdlock pthread_rwlock_rdlock
#define rwlock_unlock pthread_rwlock_unlock
#define rwlock_wrlock pthread_rwlock_wrlock
#define rwlock_destory pthread_rwlock_destroy
typedef pthread_rwlock_t rwlock_t ;

#else
#error "Not supported now"
#endif

#endif
