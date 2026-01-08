#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t elem_size;
    size_t size;
    size_t capacity;
} vector;

int vector_init(vector *v, size_t elem_size, size_t initial_cap);
void vector_free(vector *v);
int vector_push(vector *v, const void *elem);
void *vector_get(vector *v, size_t index);
int vector_set(vector *v, size_t index, const void *elem);
void vector_clear(vector *v);
size_t vector_size(const vector *v);
