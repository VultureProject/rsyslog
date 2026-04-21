#!/bin/bash
# omsentinel-multi-worker.sh
# Sends NUMMESSAGES individually (queue.dequeueBatchSize=1) on multiple workers (queue.workerThreads="4"), verifies all arrive.
. ${srcdir:=.}/diag.sh init

omsentinel_gen_certs
omsentinel_start_server 0

export NUMMESSAGES=1000

generate_conf
add_conf '
module(load="../plugins/omsentinel/.libs/omsentinel")

template(name="tpl" type="string"
    string="{\"msgnum\":\"%msg:F,58:2%\"}")

if $msg contains "msgnum:" then
    action(
        name="omsentinel_action"
        type="omsentinel"
        errorfile="'$RSYSLOG_DYNNAME/omsentinel.error.log'"
        template="tpl"

        stream_name="MyStream"
        dce="127.0.0.1:'$OMSENTINEL_PORT'"
        dcr="test-dcr-id"
        tenant_id="test-tenant"
        client_id="test-client-id"
        client_secret="test-secret"
        auth_domain="127.0.0.1:'$OMSENTINEL_PORT'"
        tls.cacert="'$SENTINEL_CERT'"

        queue.dequeueBatchSize="1"
        action.resumeRetryCount="-1"
        queue.type="FixedArray"
        queue.workerThreads="4"
        queue.highWatermark="10"
    )
'

startup
injectmsg
shutdown_when_empty
wait_shutdown
omsentinel_get_data
omsentinel_stop_server
seq_check
exit_test
