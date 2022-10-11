/* mmtaghostname.c
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

#include <tensorflow/lite/c/c_api.h>
#include <faup/faup.h>
#include <faup/decode.h>
#include <faup/output.h>

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
	faup_options_t* pFaupOpts;
	TfLiteInterpreterOptions* pTfOpts;
	TfLiteModel* pTfModel;
	size_t cacheSize;
	lfu_cache_t cache;
	} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
	TfLiteInterpreter* pInterp;
	faup_handler_t* pFaupHandler;
	double time;
	long int nb;
	int cache_hit;
	double wait_time;
} wrkrInstanceData_t;


int token(char a){
    switch(a){
        case '.': return 1;
        case '-': return 2;
        case '_': return 3;
        case '0': return 4;
        case '1': return 5;
        case '2': return 6;
        case '3': return 7;
        case '4': return 8;
        case '5': return 9;
        case '6': return 10;
        case '7': return 11;
        case '8': return 12;
        case '9': return 13;
        case 'a': return 14;
        case 'b': return 15;
        case 'c': return 16;
        case 'd': return 17;
        case 'e': return 18;
        case 'f': return 19;
        case 'g': return 20;
        case 'h': return 21;
        case 'i': return 22;
        case 'j': return 23;
        case 'k': return 24;
        case 'l': return 25;
        case 'm': return 26;
        case 'n': return 27;
        case 'o': return 28;
        case 'p': return 29;
        case 'q': return 30;
        case 'r': return 31;
        case 's': return 32;
        case 't': return 33;
        case 'u': return 34;
        case 'v': return 35;
        case 'w': return 36;
        case 'x': return 37;
        case 'y': return 38;
        case 'z': return 39;
        case 'A': return 40;
        case 'B': return 41;
        case 'C': return 42;
        case 'D': return 43;
        case 'E': return 44;
        case 'F': return 45;
        case 'G': return 46;
        case 'H': return 47;
        case 'I': return 48;
        case 'J': return 49;
        case 'K': return 50;
        case 'L': return 51;
        case 'M': return 52;
        case 'N': return 53;
        case 'O': return 54;
        case 'P': return 55;
        case 'Q': return 56;
        case 'R': return 57;
        case 'S': return 58;
        case 'T': return 59;
        case 'U': return 60;
        case 'V': return 61;
        case 'W': return 62;
        case 'X': return 63;
        case 'Y': return 64;
        case 'Z': return 65;
        default:  return 0;
    }
}

void tf_custom_error(void* user_data, const char* format, va_list args) {
    // DBGPRINTF("mmdga::%s: Error TFLite ", (const char*)user_data);
	// use user_data as stage, but tf opts need to be pushed to worker instead of instance to avoid race condition
    DBGPRINTF("mmdga:: TFLite: ", (const char*)user_data);
    DBGPRINTF(format, args);
    DBGPRINTF("\n");
}

rsRetVal preprocess(const uchar* domain, faup_handler_t* fh, uchar** processedDomain) {
	if(faup_decode(fh, domain, strlen(domain)) == NULL) {
		return RS_RET_ERR;
	}
	size_t processedDomainLen = faup_get_domain_without_tld_size(fh) + faup_get_tld_size(fh) + 2;
	*processedDomain = (uchar*)malloc(sizeof(uchar)*(processedDomainLen));

	if(*processedDomain == NULL){
		return RS_RET_OUT_OF_MEMORY;
	}

	memcpy(*processedDomain, domain + faup_get_domain_without_tld_pos(fh), faup_get_domain_without_tld_size(fh));
	memcpy(*processedDomain + faup_get_domain_without_tld_size(fh) + 1, domain + faup_get_tld_pos(fh), faup_get_tld_size(fh));
	(*processedDomain)[faup_get_domain_without_tld_size(fh)] = '.';
	(*processedDomain)[processedDomainLen-1] = '\0';
	DBGPRINTF("domain: '%s', proc len: %lu\n", domain, processedDomainLen);
	DBGPRINTF("domain: '%s' processed, proc len: %lu\n", *processedDomain, strlen(*processedDomain));
	return RS_RET_OK;
}

rsRetVal process(const uchar* input, const TfLiteInterpreter* interpreter, double* score) {
	TfLiteStatus tfiRet;
    float score_f;

	float domain[80] = {0.0f};
    size_t inputLen = strlen(input);

	
	DBGPRINTF("Processing %s with model\n", input);
    for(int i=79; i>79-inputLen; i--){
        domain[i] = (float)token(input[inputLen-1-(79-i)]);
    }

    size_t domainSize = sizeof(domain);
	
	TfLiteTensor* pInput = TfLiteInterpreterGetInputTensor(interpreter, 0);
	if(pInput == NULL){
		DBGPRINTF("mmdga::doAction::process: Error while TfLiteInterpreterGetInputTensor\n");
		return RS_RET_ERR;
	}
    
    size_t size = TfLiteTensorByteSize(pInput);
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

	pWrkrData->pFaupHandler = faup_init(pWrkrData->pData->pFaupOpts);

	pWrkrData->time = 0;
	pWrkrData->nb = 0;

	pWrkrData->cache_hit = 0;
	pWrkrData->wait_time = 0;

ENDcreateWrkrInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
	double total_ms = pWrkrData->time;
	double mean = total_ms / (double)pWrkrData->nb;
	printf("\nTIME FOR MMDGA : %f ms, %lu calls, %f ms/call\n", total_ms, pWrkrData->nb, mean);
	printf("CACHE WAIT TIME : %f us for %d cache hits\n", pWrkrData->wait_time, pWrkrData->cache_hit);
    TfLiteInterpreterDelete(pWrkrData->pInterp);
	faup_terminate(pWrkrData->pFaupHandler);
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
	pData->pFaupOpts = NULL;
	pData->pTfOpts = NULL;
	pData->pTfModel = NULL;
	pData->cacheSize = 0;
ENDcreateInstance

BEGINfreeInstance
CODESTARTfreeInstance
	free(pData->modelPath);
	free(pData->domainInputField);
	free(pData->scoreOutputField);
	faup_options_free(pData->pFaupOpts);
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
	char* tf_ver = TfLiteVersion();

	DBGPRINTF("MMDGA::NewInstance: TENSORFLITE LITE VERSION : %s\n", tf_ver);
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

	pData->pFaupOpts = faup_options_new();

	pData->cache = LFUCacheCreate(pData->cacheSize);

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
	struct timespec start, end, cache_start, cache_end; 
CODESTARTdoAction
	pWrkrData->nb++;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	DBGPRINTF("Message will now be managed by mmdga\n");

	msgPropDescr_t propDesc;
	msgPropDescrFill(&propDesc, (uchar *)pData->domainInputField, strlen(pData->domainInputField));

	struct json_object * pDummy = NULL;
	uchar* domain = NULL;
	CHKiRet(msgGetJSONPropJSONorString(pMsg, &propDesc, &pDummy, &domain));

	if(pDummy != NULL) {
		DBGPRINTF("mmdga::doAction: domain is not string\n");
		FINALIZE;
	}

	double score = -1.0f;
	char * processed_domain = NULL;

	CHKiRet(preprocess(domain, pWrkrData->pFaupHandler, &processed_domain));
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cache_start);
	bool read = LFURead(&pData->cache, processed_domain, &score);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cache_end);
	if(!read){
		CHKiRet(process(processed_domain, pWrkrData->pInterp, &score));
		LFUWrite(&pData->cache, processed_domain, score);
	} else {
		pWrkrData->cache_hit++;
	}


	CHKiRet(msgAddJSON(pMsg, pData->scoreOutputField, json_object_new_double(score), 0, 0));

finalize_it:
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	struct timespec d = diff(start, end);
	pWrkrData->time += d.tv_nsec/1000000.0;

	struct timespec d_cache = diff(cache_start, cache_end);
	pWrkrData->wait_time += d_cache.tv_nsec/1000.0;

	free(domain);
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
