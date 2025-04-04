#pragma once

#include <stdbool.h>
#include <pthread.h>

struct thread_task;

struct task_vector {
	pthread_mutex_t mutex;
	struct thread_task **tasks;
	size_t size;
	size_t capacity;
};

int
task_vector_init(struct task_vector *vector);

int
task_vector_realloc(struct task_vector *vector);

struct thread_task *
task_vector_pop_front(struct task_vector *vector);

int
task_vector_push_back(struct task_vector *vector, struct thread_task *task);

size_t
task_vector_size(struct task_vector *vector);

void
task_vector_delete(struct task_vector *vector);

bool
task_vector_contains(struct task_vector *vector, struct thread_task *task);


