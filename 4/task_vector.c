#include "task_vector.h"

#include <stdlib.h>
#include <string.h>

#define VECTOR_INIT_SIZE 10
#define VECTOR_GROW_COEF 2

inline int
task_vector_init(struct task_vector *vector) {
	pthread_mutex_init(&vector->mutex, NULL);
	vector->tasks = calloc(VECTOR_INIT_SIZE, sizeof(struct thread_task *));
	if (vector->tasks == NULL) {
		pthread_mutex_destroy(&vector->mutex);
		return 1;
	}

	vector->size = 0;
	vector->capacity = VECTOR_INIT_SIZE;
	return 0;
}

inline int
task_vector_realloc(struct task_vector *vector)
{
	size_t new_capacity = 0;
	if (vector->size == vector->capacity) {
		new_capacity = vector->capacity * VECTOR_GROW_COEF;
	}
	else if (vector->size * VECTOR_GROW_COEF < vector->capacity && vector->capacity > VECTOR_INIT_SIZE) {
		new_capacity = vector->capacity / VECTOR_GROW_COEF;
	}

	if (new_capacity != 0) {
		struct thread_task **new_tasks = realloc(vector->tasks, new_capacity * sizeof(struct thread_task *));
		if (new_tasks == NULL) {
			return 1;
		}

		if (new_capacity > vector->capacity) {
			memset(new_tasks + vector->capacity, 0, (new_capacity - vector->capacity) * sizeof(struct thread_task *));
		}

		vector->tasks = new_tasks;
		vector->capacity = new_capacity;
	}

	return 0;
}

inline struct thread_task *
task_vector_pop_front(struct task_vector *vector)
{
	struct thread_task *result = NULL;
	pthread_mutex_lock(&vector->mutex);

	if (vector->size == 0) {
		pthread_mutex_unlock(&vector->mutex);
		return NULL;
	}

	result = vector->tasks[0];

	--vector->size;
	if (vector->size > 0) {
		memmove(vector->tasks, vector->tasks + 1, sizeof(struct thread_task *) * vector->size);
	}
	task_vector_realloc(vector);

	pthread_mutex_unlock(&vector->mutex);
	return result;
}

inline int
task_vector_push_back(struct task_vector *vector, struct thread_task *task)
{
	pthread_mutex_lock(&vector->mutex);

	if (task_vector_realloc(vector) != 0) {
		pthread_mutex_unlock(&vector->mutex);
		return 1;
	}

	vector->tasks[vector->size++] = task;
	pthread_mutex_unlock(&vector->mutex);
	return 0;
}

inline size_t
task_vector_size(struct task_vector *vector)
{
	size_t result;
	pthread_mutex_lock(&vector->mutex);
	result = vector->size;
	pthread_mutex_unlock(&vector->mutex);
	return result;
}

inline void
task_vector_delete(struct task_vector *vector)
{
	pthread_mutex_destroy(&vector->mutex);
	free(vector->tasks);
}

inline bool
task_vector_contains(struct task_vector *vector, struct thread_task *task)
{
	pthread_mutex_lock(&vector->mutex);

	for (size_t i = 0; i < vector->size; ++i) {
		if (vector->tasks[i] == task) {
			pthread_mutex_unlock(&vector->mutex);
			return true;
		}
	}

	pthread_mutex_unlock(&vector->mutex);
	return false;
}

