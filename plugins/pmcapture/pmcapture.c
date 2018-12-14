/* pmcapture.c
 *
 * This is a parser intended to work in coordination with impcap.
 * This module gets data from the impcap module, and follow streams
 * to capture relevant data, such as files, from packets.
 *
 * File begun on 2018-11-13
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

 #include "rsyslog.h"
 #include "errmsg.h"
 #include "unicode-helper.h"
 #include "module-template.h"
 #include "rainerscript.h"
 #include "rsconf.h"

MODULE_TYPE_PARSER
MODULE_TYPE_NOKEEP
PARSER_NAME("rsyslog.pmcapture")
MODULE_CNFNAME("pmcapture")

/* static data */
DEF_IMOD_STATIC_DATA

static char* proto_list[] = {
  "http",
  "ftp",
  "smb"
};

/* conf structures */

struct instanceConf_s {
  uchar* protocol;
  uchar* folder;
  struct instanceConf_s *next;
};

/* input instance parameters */
static struct cnfparamdescr parspdescr[] = {
	{ "protocol", eCmdHdlrString, 0 },
  { "folder", eCmdHdlrString, 0 }
};
static struct cnfparamblk parspblk =
{ CNFPARAMBLK_VERSION,
  sizeof(parspdescr)/sizeof(struct cnfparamdescr),
  parspdescr
};

/* create parser instance, set default parameters */
static rsRetVal
createInstance(instanceConf_t **pinst)
{
	instanceConf_t *inst;
	DEFiRet;
	CHKmalloc(inst = malloc(sizeof(instanceConf_t)));

  inst->protocol = NULL;

	*pinst = inst;
finalize_it:
	RETiRet;
}

/* parser instances */

BEGINnewParserInst
  struct cnfparamvals *pvals = NULL;
  int i;
CODESTARTnewParserInst
  DBGPRINTF("pmcapture: begin newParserInst\n");

  inst = NULL;
  CHKiRet(createInstance(&inst));

  if(lst == NULL)
    FINALIZE;

  pvals = nvlstGetParams(lst, &parspblk, NULL);
  if(pvals == NULL) {
    LogError(0, RS_RET_MISSING_CNFPARAMS,
              "pmcapture: required parameters are missing\n");
    ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
  }

  for(i = 0 ; i < parspblk.nParams ; ++i) {
    if(!pvals[i].bUsed)
      continue;
    if(!strcmp(parspblk.descr[i].name, "protocol")) {
      inst->protocol = (uchar*) es_str2cstr(pvals[i].val.d.estr, NULL);
    }
    else if(!strcmp(parspblk.descr[i].name, "folder")) {
      inst->folder = (uchar*) es_str2cstr(pvals[i].val.d.estr, NULL);
    }
    else {
      dbgprintf("pmcapture: non-handled param %s in beginCnfLoad\n", parspblk.descr[i].name);
    }
  }

finalize_it:
CODE_STD_FINALIZERnewParserInst
  cnfparamvalsDestruct(pvals, &parspblk);
ENDnewParserInst

BEGINfreeParserInst
CODESTARTfreeParserInst
ENDfreeParserInst

/* runtime functions */

BEGINparse2
CODESTARTparse2
ENDparse2

BEGINmodExit
CODESTARTmodExit
ENDmodExit

/* declaration of functions */

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_PMOD2_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
  *ipIFVersProvided = CURR_MOD_IF_VERSION;
ENDmodInit
