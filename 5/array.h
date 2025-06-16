#pragma once

#include "chat.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define ARR_INIT_SIZE 10
#define ARR_GROW_COEFF 2

typedef struct chat_message *arr_type;

struct array {
	size_t a_size;
	size_t a_capacity;
	arr_type *a_elems;
};

static inline int
array_init(struct array *arr)
{
	assert(arr != NULL);
	arr->a_size = 0;
	arr->a_capacity = ARR_INIT_SIZE;
	arr->a_elems = calloc(arr->a_capacity, sizeof(arr_type));
	if (arr->a_elems == NULL) {
		return 1;
	}

	return 0;
}

static inline void
array_free(struct array *arr)
{
	assert(arr != NULL);
	free(arr->a_elems);
}

static inline int
array_realloc(struct array *arr)
{
	assert(arr != NULL);

	size_t new_capacity = 0;

	if (arr->a_size * ARR_GROW_COEFF < arr->a_capacity && arr->a_size > ARR_INIT_SIZE) {
		new_capacity = arr->a_capacity / ARR_GROW_COEFF;
	}

	if (arr->a_size == arr->a_capacity) {
		new_capacity = arr->a_capacity * ARR_GROW_COEFF;
	}

	if (new_capacity != 0) {
		arr_type *new_children = realloc(arr->a_elems, sizeof(arr_type) * new_capacity);
		if (new_children == NULL) {
			return 1;
		}

		arr->a_elems = new_children;
		arr->a_capacity = new_capacity;
		return 0;
	}

	return 0;
}

static inline int
array_push(struct array *arr, arr_type child)
{
	assert(arr != NULL);
	arr->a_elems[arr->a_size++] = child;
	return array_realloc(arr);
}

static inline arr_type
array_pop(struct array *arr, size_t index)
{
	assert(arr != NULL);

	if (arr->a_size == 0) {
		return NULL;
	}

	arr_type copy = arr->a_elems[index];
	memmove(arr->a_elems + index, arr->a_elems + index + 1, sizeof(arr_type) * (arr->a_size - index - 1));
	--arr->a_size;

	array_realloc(arr);
	return copy;
}

static inline arr_type
array_at(const struct array *arr, size_t index)
{
	assert(arr != NULL);

	if (arr->a_size <= index) {
		return NULL;
	}

	return arr->a_elems[index];
}
