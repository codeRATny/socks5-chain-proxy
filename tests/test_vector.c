#undef NDEBUG
#include <assert.h>
#include <string.h>
#include "vector.h"

int main(void) {
    vector v;
    assert(vector_init(&v, sizeof(int), 2)==0);
    for(int i=0;i<10;++i) assert(vector_push(&v, &i)==0);
    assert(vector_size(&v)==10);
    for(size_t i=0;i<vector_size(&v);++i) {
        int *p = (int*)vector_get(&v, i);
        assert(p && *p==(int)i);
    }
    int val=42;
    assert(vector_set(&v, 5, &val)==0);
    int *p = (int*)vector_get(&v,5);
    assert(p && *p==42);
    /* set out of bounds should fail */
    assert(vector_set(&v, 50, &val)!=0);
    /* get out of bounds returns NULL */
    assert(vector_get(&v, 50)==NULL);
    /* push many to force grow */
    for(int i=0;i<100;++i) assert(vector_push(&v, &i)==0);
    assert(vector_size(&v)==110);
    vector_clear(&v);
    assert(vector_size(&v)==0);
    vector_free(&v);

    /* invalid init and operations */
    assert(vector_init(&v, 0, 0)!=0);
    assert(vector_push(NULL, &val)!=0);
    assert(vector_push(&v, NULL)!=0);
    assert(vector_set(NULL, 0, &val)!=0);
    assert(vector_get(NULL, 0)==NULL);
    vector_free(NULL);
    return 0;
}
