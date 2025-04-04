#include "thread_pool.h"
#include "task_vector.h"

#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#define NSEC_PER_SEC 1000000000

enum task_state {
	TASK_CREATED,
	TASK_PUSHED,
	TASK_RUNNING,
	TASK_FINISHED,
};

struct thread_task {
	enum task_state state;

	thread_task_f function;
	void *arg;
	void *result;

	pthread_mutex_t mutex;
	pthread_cond_t cond;

	bool need_detach;
};

struct thread_pool;

enum thread_state {
	THREAD_RUNNING,
	THREAD_FINISHED,
};

struct thread {
	pthread_t thread;
	struct thread_pool *parent;
	bool task_running;
};

struct thread_pool {
	struct thread **threads;
	int max_thread_count;

	pthread_mutex_t queue_mutex;
	pthread_cond_t queue_cond;
	struct task_vector tasks_queue;

	bool about_to_delete;
};

static bool
get_atomic_bool(const bool *atomic)
{
	bool status;
	__atomic_load(atomic, &status, __ATOMIC_SEQ_CST);
	return status;
}

static void
set_atomic_bool(bool *atomic, bool new_value)
{
	__atomic_store(atomic, &new_value, __ATOMIC_SEQ_CST);
}

static enum task_state
get_task_status(const struct thread_task *task)
{
	enum task_state result;
	__atomic_load(&task->state, &result, __ATOMIC_SEQ_CST);
	return result;
}

static void
set_task_status(struct thread_task *task, enum task_state status)
{
	__atomic_store(&task->state, &status, __ATOMIC_SEQ_CST);
}

static void *
thread_loop(void *tt)
{
	struct thread *this_thread = tt;
	struct thread_pool *thread_pool = this_thread->parent;
	set_atomic_bool(&this_thread->task_running, false);

	while (true) {
		struct thread_task *task = task_vector_pop_front(&thread_pool->tasks_queue);
		while (task != NULL) {
			set_atomic_bool(&this_thread->task_running, true);

			set_task_status(task, TASK_RUNNING);
			task->result = task->function(task->arg);
			set_task_status(task, TASK_FINISHED);

			set_atomic_bool(&this_thread->task_running, false);

			if (get_atomic_bool(&task->need_detach)) {
				thread_task_delete(task);
			}
			else {
				pthread_mutex_lock(&task->mutex);
				pthread_cond_signal(&task->cond);
				pthread_mutex_unlock(&task->mutex);
			}

			task = task_vector_pop_front(&thread_pool->tasks_queue);
		}

		bool delete_flag;
		__atomic_load(&thread_pool->about_to_delete, &delete_flag, __ATOMIC_SEQ_CST);
		if (delete_flag) {
			break;
		}

		pthread_mutex_lock(&thread_pool->queue_mutex);
		pthread_cond_wait(&thread_pool->queue_cond, &thread_pool->queue_mutex);
		pthread_mutex_unlock(&thread_pool->queue_mutex);
	}

	return NULL;
}

int
thread_pool_new(int max_thread_count, struct thread_pool **pool)
{
	if (max_thread_count <= 0 || max_thread_count > TPOOL_MAX_THREADS) {
		return TPOOL_ERR_INVALID_ARGUMENT;
	}

	struct thread_pool *result = calloc(1, sizeof(struct thread_pool));
	if (result == NULL) {
		return TPOOL_ERR_UNKNOWN;
	}

	result->threads = calloc(max_thread_count, sizeof(struct thread *));
	if (result->threads == NULL) {
		free(result);
		return TPOOL_ERR_UNKNOWN;
	}

	if (task_vector_init(&result->tasks_queue) != 0) {
		free(result->threads);
		free(result);
		return TPOOL_ERR_UNKNOWN;
	}

	if (pthread_mutex_init(&result->queue_mutex, NULL) != 0) {
		task_vector_delete(&result->tasks_queue);
		free(result->threads);
		free(result);
		return TPOOL_ERR_UNKNOWN;
	}

	if (pthread_cond_init(&result->queue_cond, NULL) != 0) {
		pthread_mutex_destroy(&result->queue_mutex);
		task_vector_delete(&result->tasks_queue);
		free(result->threads);
		free(result);
		return TPOOL_ERR_UNKNOWN;
	}

	result->max_thread_count = max_thread_count;
	result->about_to_delete = false;

	*pool = result;
	return 0;
}

int
thread_pool_thread_count(const struct thread_pool *pool)
{
	int result = 0;
	while (result < pool->max_thread_count && pool->threads[result] != NULL) {
		++result;
	}

	return result;
}

int
thread_pool_delete(struct thread_pool *pool)
{
	if (task_vector_size(&pool->tasks_queue) != 0) {
		return TPOOL_ERR_HAS_TASKS;
	}

	for (int i = 0; i < pool->max_thread_count && pool->threads[i] != NULL; ++i) {
		if (get_atomic_bool(&pool->threads[i]->task_running)) {
			return TPOOL_ERR_HAS_TASKS;
		}
	}

	bool new_state = true;
	__atomic_store(&pool->about_to_delete, &new_state, __ATOMIC_SEQ_CST);
	pthread_cond_broadcast(&pool->queue_cond);

	for (int i = 0; i < pool->max_thread_count && pool->threads[i] != NULL; ++i) {
		pthread_join(pool->threads[i]->thread, NULL);
		free(pool->threads[i]);
	}

	free(pool->threads);
	task_vector_delete(&pool->tasks_queue);
	pthread_mutex_destroy(&pool->queue_mutex);
	pthread_cond_destroy(&pool->queue_cond);

	free(pool);

	return 0;
}

int
thread_pool_push_task(struct thread_pool *pool, struct thread_task *task)
{
	if (task_vector_size(&pool->tasks_queue) >= TPOOL_MAX_TASKS) {
		return TPOOL_ERR_TOO_MANY_TASKS;
	}

	set_task_status(task, TASK_PUSHED);
	task_vector_push_back(&pool->tasks_queue, task);

	int i = 0;
	while (i < pool->max_thread_count && pool->threads[i] != NULL) {
		bool is_thread_running;
		__atomic_load(&pool->threads[i]->task_running, &is_thread_running, __ATOMIC_SEQ_CST);
		if (is_thread_running) {
			++i;
			continue;
		}

		pthread_cond_signal(&pool->queue_cond);
		return 0;
	}

	if (i == pool->max_thread_count) {
		return 0;
	}

	pool->threads[i] = calloc(1, sizeof(struct thread));
	if (pool->threads[i] == NULL) {
		return TPOOL_ERR_UNKNOWN;
	}

	pool->threads[i]->task_running = false;
	pool->threads[i]->parent = pool;

	if (pthread_create(&pool->threads[i]->thread, NULL, thread_loop, pool->threads[i]) != 0) {
		return TPOOL_ERR_UNKNOWN;
	}

	return 0;
}

int
thread_task_new(struct thread_task **task, thread_task_f function, void *arg)
{
	struct thread_task *result = calloc(1, sizeof(struct thread_task));
	if (result == NULL) {
		return TPOOL_ERR_UNKNOWN;
	}

	if (pthread_mutex_init(&result->mutex, NULL) != 0) {
		free(result);
		return TPOOL_ERR_UNKNOWN;
	}

	if (pthread_cond_init(&result->cond, NULL) != 0) {
		pthread_mutex_destroy(&result->mutex);
		free(result);
		return TPOOL_ERR_UNKNOWN;
	}

	set_task_status(result, TASK_CREATED);
	result->function = function;
	result->arg = arg;
	result->need_detach = false;

	*task = result;

	return 0;
}

bool
thread_task_is_finished(const struct thread_task *task)
{
	return get_task_status(task) == TASK_FINISHED;
}

bool
thread_task_is_running(const struct thread_task *task)
{
	return get_task_status(task) == TASK_RUNNING;
}

int
thread_task_join(struct thread_task *task, void **result)
{
	if (get_task_status(task) == TASK_CREATED) {
		return TPOOL_ERR_TASK_NOT_PUSHED;
	}

	pthread_mutex_lock(&task->mutex);

	while (get_task_status(task) != TASK_FINISHED) {
		pthread_cond_wait(&task->cond, &task->mutex);
	}

	pthread_mutex_unlock(&task->mutex);
	set_task_status(task, TASK_CREATED);
	*result = task->result;

	return 0;
}

#if NEED_TIMED_JOIN

int
thread_task_timed_join(struct thread_task *task, double timeout, void **result)
{
	if (get_task_status(task) == TASK_CREATED) {
		return TPOOL_ERR_TASK_NOT_PUSHED;
	}

	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		return TPOOL_ERR_UNKNOWN;
	}

	long long timeout_nsec = (long)(timeout * NSEC_PER_SEC);
	ts.tv_sec += timeout_nsec / NSEC_PER_SEC;
	ts.tv_nsec += timeout_nsec % NSEC_PER_SEC;

	if (ts.tv_nsec >= NSEC_PER_SEC) {
		ts.tv_nsec -= NSEC_PER_SEC;
		ts.tv_sec += 1;
	}

	pthread_mutex_lock(&task->mutex);

	int ret_code = pthread_cond_timedwait(&task->cond, &task->mutex, &ts);
	while (ret_code == 0 && get_task_status(task) != TASK_FINISHED) {
		ret_code = pthread_cond_timedwait(&task->cond, &task->mutex, &ts);
	}

	if (ret_code == ETIMEDOUT) {
		pthread_mutex_unlock(&task->mutex);
		return TPOOL_ERR_TIMEOUT;
	}

	pthread_mutex_unlock(&task->mutex);
	set_task_status(task, TASK_CREATED);
	*result = task->result;

	return 0;
}

#endif

int
thread_task_delete(struct thread_task *task)
{
	switch (get_task_status(task)) {
	case TASK_RUNNING:
	case TASK_PUSHED: {
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
	if (get_task_status(task) == TASK_CREATED) {
		return TPOOL_ERR_TASK_NOT_PUSHED;
	}

	pthread_mutex_lock(&task->mutex);
	set_atomic_bool(&task->need_detach, true);
	pthread_mutex_unlock(&task->mutex);

	return 0;
}

#endif
