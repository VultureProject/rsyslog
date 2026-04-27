#!/bin/bash
# omsentinel-compression.sh
# Sends NUMMESSAGES in batch mode with compress="on" (default zlib level),
# verifies all arrive correctly and every ingest POST was gzip-encoded.
. ${srcdir:=.}/diag.sh init

export TB_TEST_MAX_RUNTIME=30
export NUMMESSAGES=1000

omsentinel_gen_certs
omsentinel_start_server 0

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

        compress="on"

        queue.dequeueBatchSize="100"
        action.resumeRetryCount="-1"
    )
'

startup
injectmsg
shutdown_when_empty
wait_shutdown
omsentinel_get_data
omsentinel_check_all_compressed
omsentinel_stop_server
seq_check
exit_test
