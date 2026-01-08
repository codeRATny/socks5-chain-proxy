#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include "queue.h"

int main(void) {
    queue q;
    assert(queue_init(&q, 0) == 0); /* zero should default to sensible size */
    int a=1,b=2,c=3; void *out=NULL;
    assert(queue_push(&q, &a)==0);
    assert(queue_push(&q, &b)==0);
    assert(queue_push(&q, &c)==0);
    assert(queue_pop(&q, &out)==0 && *(int*)out==1);
    assert(queue_pop(&q, &out)==0 && *(int*)out==2);
    assert(queue_pop(&q, &out)==0 && *(int*)out==3);
    assert(queue_empty(&q)!=0);

    /* pop on empty should fail */
    assert(queue_pop(&q, &out)!=0);

    /* pop with NULL out pointer should still succeed */
    assert(queue_push(&q, &a)==0);
    assert(queue_pop(&q, NULL)==0);

    /* wrap-around and grow */
    int vals[20];
    for (int i=0;i<20;++i) {
        vals[i]=i;
        assert(queue_push(&q, &vals[i])==0);
        if (i%3==0) {
            assert(queue_pop(&q, &out)==0);
        }
    }
    int consumed=0;
    while(queue_pop(&q,&out)==0) consumed++;
    assert(consumed>0);
    queue_free(&q);

    /* api should tolerate NULL queue pointer */
    assert(queue_empty(NULL)!=0);
    queue_free(NULL);
    assert(queue_push(NULL, &a)!=0);
    assert(queue_pop(NULL, &out)!=0);
    return 0;
}
