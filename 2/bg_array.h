#pragma once

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/wait.h>

#define BG_PROC_ARR_INIT_SIZE 10
#define BG_PROC_ARR_GROW_COEFF 2

struct bg_array {
	size_t bg_size;
	size_t bg_capacity;
	pid_t *children;
};

static inline int
bg_array_init(struct bg_array *arr)
{
	assert(arr != NULL);
	arr->bg_size = 0;
	arr->bg_capacity = BG_PROC_ARR_INIT_SIZE;
	arr->children = calloc(arr->bg_capacity, sizeof(pid_t));
	if (arr->children == NULL) {
		return 1;
	}

	return 0;
}

static inline int
bg_array_realloc(struct bg_array *arr)
{
	assert(arr != NULL);

	size_t new_capacity = 0;

	if (arr->bg_size * BG_PROC_ARR_GROW_COEFF < arr->bg_capacity && arr->bg_size > BG_PROC_ARR_INIT_SIZE) {
		new_capacity = arr->bg_capacity / BG_PROC_ARR_GROW_COEFF;
	}

	if (arr->bg_size == arr->bg_capacity) {
		new_capacity = arr->bg_capacity * BG_PROC_ARR_GROW_COEFF;
	}

	if (new_capacity != 0) {
		pid_t *new_children = realloc(arr->children, sizeof(pid_t) * new_capacity);
		if (new_children == NULL) {
			return 1;
		}

		arr->children = new_children;
		arr->bg_capacity = new_capacity;
		return 0;
	}

	return 0;
}

static inline int
bg_array_wait_nonblock(struct bg_array *arr)
{
	assert(arr != NULL);

	for (size_t i = 0; i < arr->bg_size;) {
		if (waitpid(arr->children[i], NULL, WNOHANG) > 0) {
			--arr->bg_size;

			if (i < arr->bg_size) {
				memmove(arr->children + i, arr->children + i + 1, sizeof(pid_t) * (arr->bg_size - i));
			}
		}
		else {
			++i;
		}
	}

	return bg_array_realloc(arr);
}

static inline int
bg_array_push(struct bg_array *arr, pid_t child)
{
	assert(arr != NULL);
	arr->children[arr->bg_size++] = child;
	return bg_array_realloc(arr);
}

static inline void
bg_array_free(struct bg_array *arr)
{
	assert(arr != NULL);
	free(arr->children);
}
