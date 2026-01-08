#include "vector.h"
#include "vector_traits.h"

int vector_init(vector *v, size_t elem_size, size_t initial_cap) {
    if (!v || elem_size == 0) return -1;
    if (initial_cap == 0) initial_cap = 8;
    v->data = (uint8_t *)V_MALLOC(elem_size * initial_cap);
    if (!v->data) return -1;
    v->elem_size = elem_size;
    v->size = 0;
    v->capacity = initial_cap;
    return 0;
}

void vector_free(vector *v) {
    if (!v) return;
    V_FREE(v->data);
    memset(v, 0, sizeof(*v));
}

static int vector_grow(vector *v) {
    size_t new_cap = v->capacity ? v->capacity * 2 : 8;
    uint8_t *nd = (uint8_t *)V_REALLOC(v->data, new_cap * v->elem_size);
    if (!nd) return -1;
    v->data = nd;
    v->capacity = new_cap;
    return 0;
}

int vector_push(vector *v, const void *elem) {
    if (!v || !elem) return -1;
    if (v->size == v->capacity) {
        if (vector_grow(v) != 0) return -1;
    }
    V_MEMCPY(v->data + v->size * v->elem_size, elem, v->elem_size);
    v->size++;
    return 0;
}

void *vector_get(vector *v, size_t index) {
    if (!v || index >= v->size) return NULL;
    return v->data + index * v->elem_size;
}

int vector_set(vector *v, size_t index, const void *elem) {
    if (!v || !elem || index >= v->size) return -1;
    V_MEMCPY(v->data + index * v->elem_size, elem, v->elem_size);
    return 0;
}

void vector_clear(vector *v) {
    if (!v) return;
    v->size = 0;
}

size_t vector_size(const vector *v) {
    return v ? v->size : 0;
}
