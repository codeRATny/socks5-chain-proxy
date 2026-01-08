#pragma once

#include <stddef.h>

struct ev_loop;

struct ev_task {
    void (*fn)(struct ev_loop *, void *);
    void *arg;
};

typedef struct {
    void **data;
    size_t cap;
    size_t head;
    size_t tail;
    size_t size;
} queue;

int queue_init(queue *q, size_t initial_cap);
void queue_free(queue *q);
int queue_push(queue *q, void *item);
int queue_pop(queue *q, void **out);
int queue_empty(const queue *q);
