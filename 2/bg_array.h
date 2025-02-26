#pragma once

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/wait.h>

#define BG_PROC_ARR_INIT_SIZE 10
#define BG_PROC_ARR_GROW_COEFF 2

struct pid_array {
	size_t pa_size;
	size_t pa_capacity;
	pid_t *pa_children;
};

static inline int
pid_array_init(struct pid_array *arr)
{
	assert(arr != NULL);
	arr->pa_size = 0;
	arr->pa_capacity = BG_PROC_ARR_INIT_SIZE;
	arr->pa_children = calloc(arr->pa_capacity, sizeof(pid_t));
	if (arr->pa_children == NULL) {
		return 1;
	}

	return 0;
}

static inline void
pid_array_free(struct pid_array *arr)
{
	assert(arr != NULL);
	free(arr->pa_children);
}

static inline int
pid_array_realloc(struct pid_array *arr)
{
	assert(arr != NULL);

	size_t new_capacity = 0;

	if (arr->pa_size * BG_PROC_ARR_GROW_COEFF < arr->pa_capacity && arr->pa_size > BG_PROC_ARR_INIT_SIZE) {
		new_capacity = arr->pa_capacity / BG_PROC_ARR_GROW_COEFF;
	}

	if (arr->pa_size == arr->pa_capacity) {
		new_capacity = arr->pa_capacity * BG_PROC_ARR_GROW_COEFF;
	}

	if (new_capacity != 0) {
		pid_t *new_children = realloc(arr->pa_children, sizeof(pid_t) * new_capacity);
		if (new_children == NULL) {
			return 1;
		}

		arr->pa_children = new_children;
		arr->pa_capacity = new_capacity;
		return 0;
	}

	return 0;
}

static inline int
pid_array_wait_nonblock(struct pid_array *arr)
{
	assert(arr != NULL);

	for (size_t i = 0; i < arr->pa_size;) {
		if (waitpid(arr->pa_children[i], NULL, WNOHANG) > 0) {
			--arr->pa_size;

			if (i < arr->pa_size) {
				memmove(arr->pa_children + i, arr->pa_children + i + 1, sizeof(pid_t) * (arr->pa_size - i));
			}
		}
		else {
			++i;
		}
	}

	return pid_array_realloc(arr);
}

static inline int
pid_array_wait_and_free(struct pid_array *arr)
{
	assert(arr != NULL);

	int last_exitcode = 0;

	for (size_t child_idx = 0; child_idx < arr->pa_size; ++child_idx) {
		int status;
		waitpid(arr->pa_children[child_idx], &status, 0);

		if (WIFEXITED(status)) {
			last_exitcode = WEXITSTATUS(status);
		}
	}

	pid_array_free(arr);

	return last_exitcode;
}

static inline int
pid_array_push(struct pid_array *arr, pid_t child)
{
	assert(arr != NULL);
	arr->pa_children[arr->pa_size++] = child;
	return pid_array_realloc(arr);
}
