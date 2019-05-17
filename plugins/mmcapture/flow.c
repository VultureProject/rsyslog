/* flow.c
 *
 * This file contains functions used for flow handling.
 *
 * File begun on 2019-05-15
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

#include "flow.h"

FlowCnf *globalFlowCnf;

void FlowInitConfig() {
    DBGPRINTF("init flow config\n");
    memset(globalFlowCnf, 0, sizeof(FlowCnf));

    DBGPRINTF("setting random value\n");
    globalFlowCnf->hash_rand = (uint32_t) getRandom();
    globalFlowCnf->hash_size = FLOW_DEFAULT_HASHSIZE;

    DBGPRINTF("global flow conf hash_rand: %u\n", globalFlowCnf->hash_rand);
    DBGPRINTF("global flow conf hash_size: %u\n", globalFlowCnf->hash_size);

    // no lock necessary here, procedure should only be called during startup
    globalFlowCnf->headFlowList = NULL;
    globalFlowCnf->flowCount = 0;
}