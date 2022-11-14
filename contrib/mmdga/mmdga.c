/* mmdga.c
 * This is a message modification module.
 *
 * The name of the module is inspired by the parser module pmnull
 * Its objectives are closed to this parser but as a message modification
 * it can be used in a different step of the message processing without
 * interfering in the parser chain process and can be applied before or
 * after parsing process.
 *
 * Its purposes are :
 * - to add a tag on message produce by input module which does not provide
 *   a tag like imudp or imtcp. Useful when the tag is used for routing the
 *   message.
 * - to force message hostname to the rsyslog valeur. The use case is
 *   application in auto-scaling systems (AWS) providing logs through udp/tcp
 *   were the name of the host is based on an ephemeral IPs with a short term
 *   meaning. In this situation rsyslog local host name is generally the
 *   auto-scaling name then logs produced by the application is affected to
 *   the application instead of the ephemeral VM.
 *
 *
 * This file is a contribution of rsyslog.
 *
 * Author : Ph. Duveau <philippe.duveau@free.fr>
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
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#include "rsyslog.h"
#include "conf.h"
#include "syslogd-types.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "cfsysline.h"
#include "dirty.h"
#include "unicode-helper.h"
#include "cache.h"
#include "tokenise.h"

#include <tensorflow/lite/c/c_api.h>
#ifdef DGA_PERFS
	#pragma message("Perfs compiled!")
#endif
#ifdef NPU_OPTIM
	#include <tensorflow/lite/c/c_api_experimental.h>
	#pragma message("NPU optim compiled!")
#endif

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmdga")

/* internal structures */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(glbl)

/* parser instance parameters */
static struct cnfparamdescr parserpdescr[] = {
	{ "model_path", eCmdHdlrString, 0 },
	{ "domain_input_field", eCmdHdlrString, 0 },
	{ "score_output_field", eCmdHdlrString, 0 },
	{ "cache_size", eCmdHdlrInt, 0 },
};
static struct cnfparamblk parserpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(parserpdescr)/sizeof(struct cnfparamdescr),
	  parserpdescr
	};

typedef struct _instanceData {
	char *modelPath;
	size_t modelPathLen;
	char* domainInputField;
	size_t domainInputFieldLen;
	char* scoreOutputField;
	size_t scoreOutputFieldLen;
	TfLiteInterpreterOptions* pTfOpts;
	TfLiteModel* pTfModel;
	size_t cacheSize;
	lfu_cache_t cache;
	} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
	TfLiteInterpreter* pInterp;
#ifdef DGA_PERFS
	double time;
	long int nb;
	int cache_hit;
	double wait_time;
#endif
} wrkrInstanceData_t;


void tf_custom_error(void* user_data, const char* format, va_list args) {
    // DBGPRINTF("mmdga::%s: Error TFLite ", (const char*)user_data);
	// use user_data as stage, but tf opts need to be pushed to worker instead of instance to avoid race condition
	DBGPRINTF("mmdga:: TFLite: ");
    if(user_data != NULL){
		DBGPRINTF("%s : ", (const char *)user_data);
	}
    DBGPRINTF(format, args);
    DBGPRINTF("\n");
}

rsRetVal process(const uchar* input, TfLiteInterpreter* interpreter, float* score) {
	TfLiteStatus tfiRet;
    float score_f;

	float domain[DOMAIN_MAX_SIZE] = {0.0f};
    const size_t domainSize = sizeof(domain);
    const size_t inputLen = strlen((const char *)input);

	
	DBGPRINTF("Processing %s with model\n", input);
	const size_t last_index = DOMAIN_MAX_SIZE-1;
    for(size_t i=last_index; i>last_index-inputLen; i--){
        domain[i] = token(input[inputLen-1-(last_index-i)]);
    }

	
	TfLiteTensor* pInput = TfLiteInterpreterGetInputTensor(interpreter, 0);
	if(pInput == NULL){
		DBGPRINTF("mmdga::doAction::process: Error while TfLiteInterpreterGetInputTensor\n");
		return RS_RET_ERR;
	}
    
    tfiRet = TfLiteTensorCopyFromBuffer(pInput, domain, domainSize);
	if(tfiRet != kTfLiteOk) {
		dbgprintf("mmdga::doAction::process: TfLiteTensorCopyFromBuffer failed with error : %d", (int)tfiRet);
		return RS_RET_ERR;
	}
    tfiRet = TfLiteInterpreterInvoke(interpreter);
	if(tfiRet != kTfLiteOk) {
		dbgprintf("mmdga::doAction::process: TfLiteInterpreterInvoke failed with error : %d", (int)tfiRet);
		return RS_RET_ERR;
	}

    const TfLiteTensor* pOutput = TfLiteInterpreterGetOutputTensor(interpreter, 0);
	if(pOutput == NULL){
		DBGPRINTF("mmdga::doAction::process: Error while TfLiteInterpreterGetOutputTensor\n");
		return RS_RET_ERR;
	}

    tfiRet = TfLiteTensorCopyToBuffer(pOutput, &score_f, sizeof(float));
	if(tfiRet != kTfLiteOk) {
		dbgprintf("mmdga::doAction::process: TfLiteInterpreterInvoke failed with error : %d", (int)tfiRet);
		return RS_RET_ERR;
	}
	*score = score_f;

	return RS_RET_OK;
}


BEGINcreateWrkrInstance
	TfLiteStatus tfiRet;

CODESTARTcreateWrkrInstance
	pWrkrData->pInterp = TfLiteInterpreterCreate(pWrkrData->pData->pTfModel, pWrkrData->pData->pTfOpts);
	if(pWrkrData->pInterp == NULL) {
		dbgprintf("mmdga::CreateWorkerInstance: TfLiteInterpreterCreate failed\n");
		return (RS_RET_ERR);
	}
	tfiRet = TfLiteInterpreterAllocateTensors(pWrkrData->pInterp);
	if(tfiRet != kTfLiteOk) {
		dbgprintf("mmdga::CreateWorkerInstance: TfLiteInterpreterAllocateTensors failed with error : %d", (int)tfiRet);
		return (RS_RET_ERR);
	}

#ifdef DGA_PERFS
	pWrkrData->time = 0;
	pWrkrData->nb = 0;

	pWrkrData->cache_hit = 0;
	pWrkrData->wait_time = 0;
#endif
ENDcreateWrkrInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
#ifdef DGA_PERFS
	double total_ms = pWrkrData->time;
	double mean = total_ms / (double)pWrkrData->nb;
	printf("\nTIME FOR MMDGA : %f ms, %lu calls, %f ms/call\n", total_ms, pWrkrData->nb, mean);
	printf("CACHE WAIT TIME : %f us for %d cache hits\n", pWrkrData->wait_time, pWrkrData->cache_hit);
#endif
    TfLiteInterpreterDelete(pWrkrData->pInterp);
ENDfreeWrkrInstance

BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
	dbgprintf("mmdga:\n");
	dbgprintf("\tmodel_path='%s'\n", pData->modelPath);
	dbgprintf("\tdomain_input_field='%s'\n", pData->domainInputField);
	dbgprintf("\tscore_output_field='%s'\n", pData->scoreOutputField);
ENDdbgPrintInstInfo

BEGINcreateInstance
CODESTARTcreateInstance
	pData->modelPath = NULL;
	pData->modelPathLen = 0;
	pData->domainInputField = NULL;
	pData->domainInputFieldLen = 0;
	pData->scoreOutputField = NULL;
	pData->scoreOutputFieldLen = 0;
	pData->pTfOpts = NULL;
	pData->pTfModel = NULL;
	pData->cacheSize = 0;
ENDcreateInstance

BEGINfreeInstance
CODESTARTfreeInstance
	LFUCacheDelete(&pData->cache);
	free(pData->modelPath);
	free(pData->domainInputField);
	free(pData->scoreOutputField);
	TfLiteInterpreterOptionsDelete(pData->pTfOpts);
	TfLiteModelDelete(pData->pTfModel);
ENDfreeInstance

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature

BEGINnewActInst
	struct cnfparamvals *pvals = NULL;
	int i;
CODESTARTnewActInst
	DBGPRINTF("newParserInst (mmdga)\n");
	DBGPRINTF("MMDGA::NewInstance: TENSORFLITE LITE VERSION : %s\n", TfLiteVersion());
	CHKiRet(createInstance(&pData));

	if(lst == NULL)
		FINALIZE;  /* just set defaults, no param block! */

	if((pvals = nvlstGetParams(lst, &parserpblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	if(Debug) {
		dbgprintf("parser param blk in mmdga:\n");
		cnfparamsPrint(&parserpblk, pvals);
	}

	for(i = 0 ; i < parserpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(parserpblk.descr[i].name, "model_path")) {
			pData->modelPath = (char *) es_str2cstr(pvals[i].val.d.estr, NULL);
			pData->modelPathLen = strlen(pData->modelPath);
		} else if(!strcmp(parserpblk.descr[i].name, "domain_input_field")) {
			pData->domainInputField = (char *) es_str2cstr(pvals[i].val.d.estr, NULL);
			pData->domainInputFieldLen = strlen(pData->domainInputField);
		} else if(!strcmp(parserpblk.descr[i].name, "score_output_field")) {
			pData->scoreOutputField = (char *) es_str2cstr(pvals[i].val.d.estr, NULL);
			pData->scoreOutputFieldLen = strlen(pData->scoreOutputField);
		} else if(!strcmp(parserpblk.descr[i].name, "cache_size")) {
			pData->cacheSize = pvals[i].val.d.n;
		} else {
			dbgprintf("program error, non-handled param '%s'\n",
				parserpblk.descr[i].name);
		}
	}

	pData->pTfModel = TfLiteModelCreateFromFile(pData->modelPath);
    if(pData->pTfModel == NULL){
        dbgprintf("mmdga::NewActInst : model load fail\n");
		ABORT_FINALIZE(RS_RET_LOAD_ERROR);
        return 0;
    }

	pData->pTfOpts = TfLiteInterpreterOptionsCreate();
    TfLiteInterpreterOptionsSetNumThreads(pData->pTfOpts, 1);
    TfLiteInterpreterOptionsSetErrorReporter(pData->pTfOpts, tf_custom_error, NULL);
#ifdef NPU_OPTIM
	TfLiteInterpreterOptionsSetUseNNAPI(pData->pTfOpts, true);
#endif

	pData->cache = LFUCacheCreate(pData->cacheSize, pData->cacheSize/10);

	CODE_STD_STRING_REQUESTnewActInst(1)
	CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
CODE_STD_FINALIZERnewActInst
	if(lst != NULL)
		cnfparamvalsDestruct(pvals, &parserpblk);
ENDnewActInst

struct timespec diff(struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

BEGINdoAction_NoStrings
	smsg_t **ppMsg = (smsg_t **) pMsgData;
	smsg_t *pMsg = ppMsg[0];
	instanceData *pData = pWrkrData->pData;
#ifdef DGA_PERFS
	struct timespec start, end, cache_start, cache_end; 
#endif
	struct json_object * pDummy = NULL;
	uchar* domain = NULL;
	msgPropDescr_t propDesc;
	float score = -1.0f;
	char * processed_domain = NULL;
CODESTARTdoAction
#ifdef DGA_PERFS
	pWrkrData->nb++;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
#endif
	DBGPRINTF("Message will now be managed by mmdga\n");

	msgPropDescrFill(&propDesc, (uchar*)pData->domainInputField, pData->domainInputFieldLen);
	DBGPRINTF("Message will now be managed by mmdga\n");
	CHKiRet(msgGetJSONPropJSONorString(pMsg, &propDesc, &pDummy, &domain));
	DBGPRINTF("Message will now be managed by mmdga\n");

	if(pDummy != NULL) {
		DBGPRINTF("mmdga::doAction: domain is not string\n");
		json_object_put(pDummy);
		FINALIZE;
	}

#ifdef DGA_PERFS
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cache_start);
#endif
	bool read = LFURead(&pData->cache, domain, &score);
#ifdef DGA_PERFS
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cache_end);
#endif
	if(!read){
		CHKiRet(process(domain, pWrkrData->pInterp, &score));
		LFUWrite(&pData->cache, domain, score);
	} 
#ifdef DGA_PERFS
	else {
		pWrkrData->cache_hit++;
	}
#endif

	CHKiRet(msgAddJSON(pMsg, (uchar *)pData->scoreOutputField, json_object_new_double(score), 0, 0));

finalize_it:
#ifdef DGA_PERFS
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	struct timespec d = diff(start, end);
	pWrkrData->time += d.tv_nsec/1000000.0;

	struct timespec d_cache = diff(cache_start, cache_end);
	pWrkrData->wait_time += d_cache.tv_nsec/1000.0;
#endif
	free(processed_domain);
	free(domain);
	msgPropDescrDestruct(&propDesc);
ENDdoAction

BEGINtryResume
CODESTARTtryResume
ENDtryResume

BEGINparseSelectorAct
CODESTARTparseSelectorAct
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct

BEGINmodExit
CODESTARTmodExit
	objRelease(glbl, CORE_COMPONENT);
ENDmodExit

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	CHKiRet(objUse(glbl, CORE_COMPONENT));
ENDmodInit
