#include "queue.h"
#include "queue_traits.h"

#include <string.h>

int queue_init(queue *q, size_t initial_cap) {
    if (!q) return -1;
    if (initial_cap == 0) initial_cap = 8;
    q->data = (void **)Q_MALLOC(initial_cap * sizeof(void *));
    if (!q->data) return -1;
    q->cap = initial_cap;
    q->head = q->tail = q->size = 0;
    return 0;
}

void queue_free(queue *q) {
    if (!q) return;
    Q_FREE(q->data);
    memset(q, 0, sizeof(*q));
}

static int queue_grow(queue *q) {
    size_t new_cap = q->cap ? q->cap * 2 : 8;
    void **nd = (void **)Q_MALLOC(new_cap * sizeof(void *));
    if (!nd) return -1;
    for (size_t i = 0; i < q->size; ++i) {
        nd[i] = q->data[(q->head + i) % q->cap];
    }
    Q_FREE(q->data);
    q->data = nd;
    q->cap = new_cap;
    q->head = 0;
    q->tail = q->size;
    return 0;
}

int queue_push(queue *q, void *item) {
    if (!q) return -1;
    if (q->size == q->cap) {
        if (queue_grow(q) != 0) return -1;
    }
    q->data[q->tail] = item;
    q->tail = (q->tail + 1) % q->cap;
    q->size++;
    return 0;
}

int queue_pop(queue *q, void **out) {
    if (!q || q->size == 0) return -1;
    if (out) *out = q->data[q->head];
    q->head = (q->head + 1) % q->cap;
    q->size--;
    return 0;
}

int queue_empty(const queue *q) {
    if (!q) return 1;
    return q->size == 0;
}
