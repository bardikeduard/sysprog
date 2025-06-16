#include "thread_pool.h"
#include "task_vector.h"

#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>

#define NSEC_PER_SEC 1000000000

enum task_state {
	TASK_CREATED,
	TASK_QUEUED,
	TASK_RUNNING,
	TASK_FINISHED,
};

struct thread_task {
	thread_task_f function;
	void *arg;
	void *result;

	volatile enum task_state state;
	volatile bool is_detached;

	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

struct thread_pool {
	pthread_t *threads;
	int max_thread_count;

	volatile int thread_count;
	volatile int tasks_in_progress;
	volatile bool shutdown_requested;

	struct task_vector tasks_queue;

	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

static void *
worker_loop(void *arg)
{
	struct thread_pool *pool = arg;

	while (true) {
		pthread_mutex_lock(&pool->mutex);

		while (task_vector_size(&pool->tasks_queue) == 0 &&
			!__atomic_load_n(&pool->shutdown_requested, __ATOMIC_SEQ_CST)) {
			pthread_cond_wait(&pool->cond, &pool->mutex);
		}

		if (__atomic_load_n(&pool->shutdown_requested, __ATOMIC_SEQ_CST) &&
			task_vector_size(&pool->tasks_queue) == 0) {
			pthread_mutex_unlock(&pool->mutex);
			break;
		}

		struct thread_task *task = task_vector_pop_front(&pool->tasks_queue);
		pthread_mutex_unlock(&pool->mutex);

		if (task == NULL) {
			continue;
		}

		__atomic_fetch_add(&pool->tasks_in_progress, 1, __ATOMIC_SEQ_CST);
		__atomic_store_n(&task->state, TASK_RUNNING, __ATOMIC_SEQ_CST);

		task->result = task->function(task->arg);

		__atomic_fetch_sub(&pool->tasks_in_progress, 1, __ATOMIC_SEQ_CST);

		pthread_mutex_lock(&task->mutex);

		__atomic_store_n(&task->state, TASK_FINISHED, __ATOMIC_SEQ_CST);
		if (__atomic_load_n(&task->is_detached, __ATOMIC_SEQ_CST)) {
			pthread_mutex_unlock(&task->mutex);
			thread_task_delete(task);
		}
		else {
			pthread_cond_broadcast(&task->cond);
			pthread_mutex_unlock(&task->mutex);
		}
	}

	return NULL;
}

int
thread_pool_new(int max_thread_count, struct thread_pool **pool)
{
	if (max_thread_count <= 0 || max_thread_count > TPOOL_MAX_THREADS) {
		return TPOOL_ERR_INVALID_ARGUMENT;
	}

	struct thread_pool *p = calloc(1, sizeof(struct thread_pool));
	if (!p) return TPOOL_ERR_UNKNOWN;

	p->threads = calloc(max_thread_count, sizeof(pthread_t));
	if (!p->threads) {
		free(p);
		return TPOOL_ERR_UNKNOWN;
	}

	p->max_thread_count = max_thread_count;

	__atomic_store_n(&p->thread_count, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&p->tasks_in_progress, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&p->shutdown_requested, false, __ATOMIC_RELAXED);

	if (task_vector_init(&p->tasks_queue) != 0) {
		free(p->threads);
		free(p);
		return TPOOL_ERR_UNKNOWN;
	}

	if (pthread_mutex_init(&p->mutex, NULL) != 0) {
		task_vector_delete(&p->tasks_queue);
		free(p->threads);
		free(p);
		return TPOOL_ERR_UNKNOWN;
	}

	if (pthread_cond_init(&p->cond, NULL) != 0) {
		task_vector_delete(&p->tasks_queue);
		pthread_mutex_destroy(&p->mutex);
		free(p->threads);
		free(p);
		return TPOOL_ERR_UNKNOWN;
	}

	*pool = p;
	return 0;
}

int
thread_pool_thread_count(const struct thread_pool *pool)
{
	return __atomic_load_n(&pool->thread_count, __ATOMIC_SEQ_CST);
}

int
thread_pool_delete(struct thread_pool *pool)
{
	pthread_mutex_lock(&pool->mutex);

	if (task_vector_size(&pool->tasks_queue) > 0 ||
		__atomic_load_n(&pool->tasks_in_progress, __ATOMIC_SEQ_CST) > 0) {
		pthread_mutex_unlock(&pool->mutex);
		return TPOOL_ERR_HAS_TASKS;
	}

	__atomic_store_n(&pool->shutdown_requested, true, __ATOMIC_SEQ_CST);
	pthread_cond_broadcast(&pool->cond);
	pthread_mutex_unlock(&pool->mutex);

	for (int i = 0; i < thread_pool_thread_count(pool); ++i) {
		pthread_join(pool->threads[i], NULL);
	}

	task_vector_delete(&pool->tasks_queue);
	pthread_mutex_destroy(&pool->mutex);
	pthread_cond_destroy(&pool->cond);

	free(pool->threads);
	free(pool);

	return 0;
}

int
thread_pool_push_task(struct thread_pool *pool, struct thread_task *task)
{
	pthread_mutex_lock(&pool->mutex);

	if (task_vector_size(&pool->tasks_queue) + __atomic_load_n(&pool->tasks_in_progress, __ATOMIC_SEQ_CST) >=
		TPOOL_MAX_TASKS) {
		pthread_mutex_unlock(&pool->mutex);
		return TPOOL_ERR_TOO_MANY_TASKS;
	}

	task_vector_push_back(&pool->tasks_queue, task);
	__atomic_store_n(&task->state, TASK_QUEUED, __ATOMIC_SEQ_CST);

	int tc = __atomic_load_n(&pool->thread_count, __ATOMIC_SEQ_CST);
	if (tc < pool->max_thread_count && __atomic_load_n(&pool->tasks_in_progress, __ATOMIC_SEQ_CST) >= tc) {
		int thread_idx = __atomic_fetch_add(&pool->thread_count, 1, __ATOMIC_RELAXED);
		if (pthread_create(&pool->threads[thread_idx], NULL, worker_loop, pool) != 0) {
			__atomic_fetch_sub(&pool->thread_count, 1, __ATOMIC_RELAXED);
		}
	}

	pthread_cond_signal(&pool->cond);
	pthread_mutex_unlock(&pool->mutex);
	return 0;
}

int
thread_task_new(struct thread_task **task, thread_task_f function, void *arg)
{
	struct thread_task *t = calloc(1, sizeof(struct thread_task));
	if (!t) return TPOOL_ERR_UNKNOWN;

	t->function = function;
	t->arg = arg;

	__atomic_store_n(&t->state, TASK_CREATED, __ATOMIC_RELAXED);
	__atomic_store_n(&t->is_detached, false, __ATOMIC_RELAXED);

	if (pthread_mutex_init(&t->mutex, NULL) != 0) {
		return TPOOL_ERR_UNKNOWN;
	}

	if (pthread_cond_init(&t->cond, NULL) != 0) {
		pthread_mutex_destroy(&t->mutex);
		return TPOOL_ERR_UNKNOWN;
	}

	*task = t;
	return 0;
}

int
thread_task_join(struct thread_task *task, void **result)
{
	if (__atomic_load_n(&task->state, __ATOMIC_SEQ_CST) == TASK_CREATED) {
		return TPOOL_ERR_TASK_NOT_PUSHED;
	}

	if (__atomic_load_n(&task->is_detached, __ATOMIC_SEQ_CST)) {
		return TPOOL_ERR_TASK_IN_POOL;
	}

	pthread_mutex_lock(&task->mutex);
	while (__atomic_load_n(&task->state, __ATOMIC_SEQ_CST) != TASK_FINISHED) {
		pthread_cond_wait(&task->cond, &task->mutex);
	}

	if (result) {
		*result = task->result;
	}

	__atomic_store_n(&task->state, TASK_CREATED, __ATOMIC_SEQ_CST);
	pthread_mutex_unlock(&task->mutex);

	return 0;
}

#if NEED_TIMED_JOIN

int
thread_task_timed_join(struct thread_task *task, double timeout, void **result)
{
	if (__atomic_load_n(&task->state, __ATOMIC_SEQ_CST) == TASK_CREATED) {
		return TPOOL_ERR_TASK_NOT_PUSHED;
	}

	if (__atomic_load_n(&task->is_detached, __ATOMIC_SEQ_CST)) {
		return TPOOL_ERR_TASK_IN_POOL;
	}

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	if (timeout < 0) timeout = 0;
	ts.tv_sec += (time_t) timeout;
	ts.tv_nsec += (long) ((timeout - (time_t) timeout) * NSEC_PER_SEC);
	if (ts.tv_nsec >= NSEC_PER_SEC) {
		ts.tv_sec++;
		ts.tv_nsec -= NSEC_PER_SEC;
	}

	pthread_mutex_lock(&task->mutex);

	int ret_code = 0;
	while (__atomic_load_n(&task->state, __ATOMIC_SEQ_CST) != TASK_FINISHED && ret_code != ETIMEDOUT) {
		ret_code = pthread_cond_timedwait(&task->cond, &task->mutex, &ts);
	}

	pthread_mutex_unlock(&task->mutex);

	if (ret_code == ETIMEDOUT) {
		return TPOOL_ERR_TIMEOUT;
	}

	if (result) {
		*result = task->result;
	}

	__atomic_store_n(&task->state, TASK_CREATED, __ATOMIC_SEQ_CST);

	return 0;
}

#endif

int
thread_task_delete(struct thread_task *task)
{
	switch (__atomic_load_n(&task->state, __ATOMIC_SEQ_CST)) {
		case TASK_QUEUED:
		case TASK_RUNNING: {
			return TPOOL_ERR_TASK_IN_POOL;
		}
		default: {
			break;
		}
	}

	pthread_mutex_destroy(&task->mutex);
	pthread_cond_destroy(&task->cond);

	free(task);

	return 0;
}

#if NEED_DETACH

int
thread_task_detach(struct thread_task *task)
{
	if (__atomic_load_n(&task->state, __ATOMIC_SEQ_CST) == TASK_CREATED) {
		return TPOOL_ERR_TASK_NOT_PUSHED;
	}

	pthread_mutex_lock(&task->mutex);

	__atomic_store_n(&task->is_detached, true, __ATOMIC_SEQ_CST);
	bool is_finished = (__atomic_load_n(&task->state, __ATOMIC_SEQ_CST) == TASK_FINISHED);

	pthread_mutex_unlock(&task->mutex);

	if (is_finished) {
		return thread_task_delete(task);
	}

	return 0;
}

#endif
