#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>

typedef unsigned char uchar;
typedef uint_least8_t bool;


struct cache_st {
    size_t capacity;
    size_t size;
    struct cache_entry_t {
        uchar domain[80];
        float score;
        atomic_uint_fast64_t usage;
    } * entries;
    atomic_int_fast8_t lock;
    atomic_size_t index;
};

typedef struct cache_st lfu_cache_t;

lfu_cache_t LFUCacheCreate(const size_t size);
bool LFURead (lfu_cache_t* pCache, const uchar* domain, float* score);
void LFUWrite(lfu_cache_t* pCache, const uchar* domain, float score);

lfu_cache_t LFUCacheCreate(const size_t capacity) {
    struct cache_entry_t * entries = malloc(capacity*sizeof(struct cache_entry_t));
    lfu_cache_t ret = {
        .capacity = capacity,
        .size = 0,
        .entries = entries,
        .lock = 0,
        .index = 0,
    };
    return ret;
}

bool LFURead(lfu_cache_t* pCache, const uchar* domain, float* score) {

    for(size_t i=0; i<pCache->size; i++){

        while(pCache->lock){
            sched_yield();
        }

        if(strncmp(domain, pCache->entries[i].domain, 80) == 0){
            pCache->entries[i].usage++;
            *score = pCache->entries[i].score;
            return 1;
        }
    }
    return 0;
}

void _remove_lfu(lfu_cache_t* pCache) {
    size_t min_idx = 0;
    size_t min_usage = pCache->entries[0].usage;
    
    for(size_t i=1; i<pCache->capacity; i++) {
        if(pCache->entries[i].usage < min_usage){
            min_idx = i;
        }
    }

    pCache->index = min_idx;
}

void LFUWrite(lfu_cache_t* pCache, const uchar* domain, float score) {
    size_t idx = 0;
    while(pCache->lock){
        sched_yield();
    }

    pCache->lock = 1;
    if(pCache->size == pCache->capacity) {
        _remove_lfu(pCache);
        idx = pCache->index;
    } else {
        idx = pCache->index++;
        pCache->size++;
    }

    strncpy(pCache->entries[pCache->index].domain, domain, 80);
    pCache->entries[pCache->index].score = score;
    pCache->entries[pCache->index].usage = 0;

    pCache->lock = 0;

}

