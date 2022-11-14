#pragma once
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>

#define DOMAIN_MAX_SIZE 80

typedef unsigned char uchar;
typedef uint_least8_t bool;

struct cache_entry_st {
    uchar domain[DOMAIN_MAX_SIZE];
    float score;
    atomic_uint_fast64_t usage;
    struct cache_entry_st * previous;
    struct cache_entry_st * next;
};

struct cache_st {
    size_t hashSize;
    size_t size;
    atomic_size_t index;
    atomic_int_fast8_t lock;

    size_t capacity;
    size_t poolIndex;
    struct cache_entry_st ** entries;
    struct cache_entry_st * pool;
};

typedef struct cache_entry_st cache_entry_t;
typedef struct cache_st lfu_cache_t;

lfu_cache_t LFUCacheCreate(const size_t size, const size_t hashSize);
bool LFURead (lfu_cache_t* pCache, const uchar* domain, float* score);
void LFUWrite(lfu_cache_t* pCache, const uchar* domain, float score);

typedef uint64_t hash_t;
typedef uint32_t seed_t;

hash_t djb_hash(const void* input, size_t len, seed_t seed) {

	const char *p = input;
	hash_t hash = 5381;
	size_t i;
	for (i = 0; i < len; i++) {
		hash = 33 * hash ^ p[i];
	}

	return hash + seed;
}

size_t my_hash(const uchar* domain, size_t nb_vals){
    
    size_t r = djb_hash(domain, strnlen((const char *)domain, DOMAIN_MAX_SIZE), 0) % nb_vals;
    DBGPRINTF("TCA hash %s : %lu\n", domain, r);

    return r;
}


lfu_cache_t LFUCacheCreate(const size_t capacity, const size_t hashSize) {
    cache_entry_t ** entries = malloc(hashSize*sizeof(cache_entry_t*));
    cache_entry_t * pool = malloc(capacity*sizeof(cache_entry_t));
    memset(pool, 0, capacity*sizeof(cache_entry_t));
    memset(entries, 0, hashSize*sizeof(cache_entry_t*));
    lfu_cache_t ret = {
        .hashSize = hashSize,
        .size = 0,
        .index = 0,
        .lock = 0,
        .capacity = capacity,
        .poolIndex = 0,
        .entries = entries,
        .pool = pool,
    };
    return ret;
}

void LFUCacheDelete(lfu_cache_t* pCache) {
    while(pCache->lock){
        sched_yield();
    }
    pCache->lock = 1;
    free(pCache->pool);
    free(pCache->entries);
    pCache->poolIndex = 0;
    pCache->capacity = 0;
    pCache->index = 0;
    pCache->size = 0;
    pCache->hashSize = 0;

    pCache->lock = 0;
}

bool LFURead(lfu_cache_t* pCache, const uchar* domain, float* score) {
    size_t h = my_hash(domain, pCache->hashSize);
    while(pCache->lock){
        sched_yield();
    }

    cache_entry_t* cur = pCache->entries[h];

    while(cur != NULL){
        if(strncmp((const char *)domain, (const char *)cur->domain, DOMAIN_MAX_SIZE) == 0){
            cur->usage++;
            *score = cur->score;
            return 1;
        }
        cur = cur->next;
    }

    return 0;
}

void _remove_lfu(lfu_cache_t* pCache) {
    size_t min_idx = 0;
    size_t min_usage = pCache->pool[0].usage;
    
    for(size_t i=1; i<pCache->capacity; i++) {
        if(pCache->pool[i].usage < min_usage){
            min_idx = i;
        }
    }
    pCache->poolIndex = min_idx;

    uchar* domain = pCache->pool[min_idx].domain;
    size_t h = my_hash(domain, pCache->hashSize);

    cache_entry_t* cur = pCache->entries[h];

    while(cur != NULL){
        if(strncmp((const char *)domain, (const char *)cur->domain, DOMAIN_MAX_SIZE) == 0){
            cur->previous->next = NULL;
            return;
        }
        cur = cur->next;
    }

}

void LFUWrite(lfu_cache_t* pCache, const uchar* domain, float score) {
    size_t idx = 0;

    size_t h = my_hash(domain, pCache->hashSize);

    while(pCache->lock){
        sched_yield();
    }

    pCache->lock = 1;
    if(pCache->size == pCache->capacity) {
        _remove_lfu(pCache);
        idx = pCache->poolIndex;
    } else {
        idx = pCache->poolIndex++;
        pCache->size++;
    }

    cache_entry_t* cur = NULL; //NULL 
    cache_entry_t* next = pCache->entries[h]; //NULL
    if(pCache->entries[h] == NULL){
        pCache->entries[h] = &pCache->pool[idx];
        next = pCache->entries[h];
    } else{
        while(next != NULL){
            cur = next;
            next = cur->next;
        }
        cur->next = &pCache->pool[idx];
        next = cur->next;
    }
    

    strncpy((char *)next->domain, (const char *)domain, DOMAIN_MAX_SIZE);
    next->score = score;
    next->usage = 0;
    next->previous=cur;
    next->next=NULL;

    pCache->lock = 0;

}

