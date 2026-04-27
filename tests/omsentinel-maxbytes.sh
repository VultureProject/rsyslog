#!/bin/bash
# omsentinel-maxbytes.sh
# Verifies that batch.maxbytes correctly splits a large rsyslog transaction into
# multiple HTTP POSTs, each within the byte ceiling.
#
# Message size: {"msgnum":"00000001"} = 20 bytes (8-digit padding from imdiag).
# computeBatchSize(4 msgs) = 86; adding a 5th = 106 > 100 -> flush at 4.
# With NUMMESSAGES=200 and queue.dequeueBatchSize=200 (one transaction):
#   expected: 50 POSTs of 4 messages each.
. ${srcdir:=.}/diag.sh init

export TB_TEST_MAX_RUNTIME=60
export NUMMESSAGES=200

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

        batch.maxbytes="100"

        queue.dequeueBatchSize="200"
        action.resumeRetryCount="-1"
    )
'

startup
injectmsg
shutdown_when_empty
wait_shutdown
omsentinel_get_data
omsentinel_check_max_batch_messages 4
omsentinel_stop_server
seq_check
exit_test
