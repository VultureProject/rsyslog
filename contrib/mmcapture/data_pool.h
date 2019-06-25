/* data_pool.h
 *
 * This file contains structures and prototypes of functions used
 * for data pools, used to manage memory inside the program.
 *
 * File begun on 2019-21-06
 *
 * Created by:
 *  - Théo Bertin (theo.bertin@advens.fr)
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef DATA_POOL_H
#define DATA_POOL_H

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include "rsyslog.h"

typedef struct DataObject_ {
    void *pObject;

    enum {
        EMPTY,
        INIT,
        AVAILABLE,
        USED
    } state;

    pthread_mutex_t mutex;

    struct DataObject_ *prev;
    struct DataObject_ *next;
} DataObject;

typedef struct DataPool_ {
    struct DataObject_ *head;
    struct DataObject_ *tail;
    uint32_t listSize;

    void* (*objectConstructor)(void *);
    void* (*objectDestructor)(void *);

    pthread_mutex_t mutex;
} DataPool;

DataObject *getOrCreateAvailableObject(DataPool *);
DataPool *createPool(void* (*objectConstructor(void *)), void* (*objectDestructor(void *)));
void destroyPool(DataPool *);

#endif /* DATA_POOL_H */
