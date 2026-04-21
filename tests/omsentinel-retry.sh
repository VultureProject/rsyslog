#!/bin/bash
# omsentinel-retry.sh
# Verifies that the module suspends and eventually delivers all messages when
# the ingest endpoint returns 500 errors periodically.
#
# The server fails every 10th ingest (of bulks of 100 messages at most) POST.  With action.resumeRetryCount="-1"
# rsyslog retries indefinitely, so every message must eventually arrive.
. ${srcdir:=.}/diag.sh init

export NUMMESSAGES=5000

omsentinel_gen_certs
# Fail every 10th ingest request with 500
omsentinel_start_server 0 --fail-ingest-every 10

generate_conf
add_conf '
module(load="../plugins/omsentinel/.libs/omsentinel")

main_queue(queue.dequeueBatchSize="2048")

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

        queue.dequeueBatchSize="100"
        action.resumeRetryCount="-1"
        action.resumeInterval="0"
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
