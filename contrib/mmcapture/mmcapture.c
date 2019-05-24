/* mmcapture.c
 *
 * This is a parser intended to work in coordination with impcap.
 * This module gets data from the impcap module, and follow TCP streams
 * to capture relevant data (such as files) from packets.
 *
 * File begun on 2018-12-5
 *
 * Created by:
 *  - François Bernard (francois.bernard@isen.yncrea.fr)
 *  - Théo Bertin (theo.bertin@isen.yncrea.fr)
 *  - Tianyu Geng (tianyu.geng@isen.yncrea.fr)
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

#include "config.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <json.h>
#include <sys/types.h>

#include "rsyslog.h"
#include "errmsg.h"
#include "unicode-helper.h"
#include "module-template.h"
#include "rainerscript.h"
#include "rsconf.h"

#include "file_utils.h"
#include "tcp_sessions.h"
#include "packets.h"
#include "flow.h"
#include "tcp_sessions.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmcapture")

/* static data */
DEF_OMOD_STATIC_DATA

#define IMPCAP_METADATA "!impcap"
#define IMPCAP_DATA     "!data"

static char* proto_list[] = {
  "http",
  "ftp",
  "smb"
};

/* conf structures */

typedef struct instanceData_s {
  char* protocol;
  char* folder;
  FlowCnf *globalFlowCnf;
} instanceData;

typedef struct wrkrInstanceData {
  instanceData *pData;
} wrkrInstanceData_t;

struct modConfData_s {
  rsconf_t *pConf;
};

static modConfData_t *loadModConf = NULL;
static modConfData_t *runModConf = NULL;

/* input instance parameters */
static struct cnfparamdescr actpdescr[] = {
	{ "protocol", eCmdHdlrString, 0 },
  { "folder", eCmdHdlrString, 0 }
};
static struct cnfparamblk actpblk =
{ CNFPARAMBLK_VERSION,
  sizeof(actpdescr)/sizeof(struct cnfparamdescr),
  actpdescr
};

/* init instance, set parameters */

BEGINbeginCnfLoad
  DBGPRINTF("entering beginCnfLoad\n");
CODESTARTbeginCnfLoad
	loadModConf = pModConf;
	pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
DBGPRINTF("entering endCnfLoad\n");
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
DBGPRINTF("entering checkCnf\n");
CODESTARTcheckCnf
ENDcheckCnf

BEGINactivateCnf
DBGPRINTF("entering activateCnf\n");
CODESTARTactivateCnf
	runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
DBGPRINTF("entering freeCnf\n");
CODESTARTfreeCnf
ENDfreeCnf

/* create instances */

BEGINcreateInstance
DBGPRINTF("entering createInstance\n");
CODESTARTcreateInstance
  pData->protocol = NULL;
  pData->folder = "/var/log/rsyslog/";  /* default folder for captured files */
  globalFlowCnf = malloc(sizeof(FlowCnf));
ENDcreateInstance

BEGINcreateWrkrInstance
DBGPRINTF("entering createWrkrInstance\n");
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance

BEGINfreeInstance
DBGPRINTF("entering freeInstance\n");
CODESTARTfreeInstance
ENDfreeInstance

BEGINfreeWrkrInstance
DBGPRINTF("entering freeWrkrInstance\n");
CODESTARTfreeWrkrInstance
ENDfreeWrkrInstance

BEGINnewActInst
DBGPRINTF("entering newActInst\n");
  struct cnfparamvals *pvals;
  uint16_t i;
CODESTARTnewActInst
  if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
    ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
  }

CODE_STD_STRING_REQUESTnewActInst(1)
  CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
  CHKiRet(createInstance(&pData));

  for(i = 0; i < actpblk.nParams; ++i) {
    if(!pvals[i].bUsed)
      continue;

    if(!strcmp(actpblk.descr[i].name, "protocol")) {
      pData->protocol = es_str2cstr(pvals[i].val.d.estr, NULL);
      DBGPRINTF("protocol set to '%s'", pData->protocol);
    }
    else if(!strcmp(actpblk.descr[i].name, "folder")) {
      pData->folder = es_str2cstr(pvals[i].val.d.estr, NULL);
      DBGPRINTF("folder set to '%s'", pData->folder);

    }
    else {
      LogError(0, RS_RET_PARAM_ERROR, "mmcapture: unhandled parameter '%s'", actpblk.descr[i].name);
    }
  }

  if(createFolder(pData->folder)){
    ABORT_FINALIZE(RS_RET_ERR);
  }

  flowInitConfig();

//  if(initTcp() == NULL){
//    ABORT_FINALIZE(RS_RET_ERR);
//  }
CODE_STD_FINALIZERnewActInst
ENDnewActInst

/* runtime functions */


BEGINdoAction_NoStrings
DBGPRINTF("entering doAction\n");
  smsg_t **ppMsg = (smsg_t **)pMsgData;
  smsg_t *pMsg = *ppMsg;
CODESTARTdoAction

  Packet *pkt = getImpcapData(pMsg);

  pkt->hash = calculatePacketFlowHash(pkt);

//  printPacketInfo(pkt);

  pkt->flow = getOrCreateFlowFromHash(pkt);

  if(pkt->proto == IPPROTO_TCP)  handleTcpFromPacket(pkt);

  freePacket(pkt);
ENDdoAction

BEGINparseSelectorAct
DBGPRINTF("entering parseSelectorAct\n");
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct

BEGINtryResume
DBGPRINTF("entering tryResume\n");
CODESTARTtryResume
ENDtryResume

BEGINisCompatibleWithFeature
DBGPRINTF("entering isCompatibleWithFeature\n");
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature

BEGINdbgPrintInstInfo
DBGPRINTF("entering dbgPrintInstInfo\n");
CODESTARTdbgPrintInstInfo
	DBGPRINTF("mmcapture\n");
ENDdbgPrintInstInfo

BEGINmodExit
CODESTARTmodExit
  DBGPRINTF("mmcapture: exit\n");
ENDmodExit

/* declaration of functions */

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
  DBGPRINTF("mmcapture: init\n");
  *ipIFVersProvided = CURR_MOD_IF_VERSION;
ENDmodInit
