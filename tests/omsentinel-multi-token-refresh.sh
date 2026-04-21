#!/bin/bash
# omsentinel-multi-token-refresh.sh
# Verifies that the module re-fetches the OAuth2 token when it expires, with several workers running.
#
# Strategy: start the server with --token-expire-secs=2.  Inject messages in
# two waves with a sleep in between so the first token has definitely expired
# before the second wave starts.  All messages must still arrive successfully,
# proving initAuth() triggered a refresh mid-run.
. ${srcdir:=.}/diag.sh init

export TB_TEST_MAX_RUNTIME=30
export NUMMESSAGES=200

omsentinel_gen_certs
# Tokens expire after 2 seconds – well below the default 3600s
omsentinel_start_server 0 --token-expire-secs 2

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

        queue.dequeueBatchSize="10"
        action.resumeRetryCount="-1"
        queue.type="FixedArray"
        queue.workerThreads="4"
        queue.highWatermark="10"
    )
'

startup

# First wave: 100 messages (0..99)
injectmsg 0 100

# Wait long enough for the first token to expire (token TTL = 2s)
sleep 3

# Second wave: 100 messages (100..199) — must trigger a token refresh
injectmsg 100 100

shutdown_when_empty
wait_shutdown

# Verify all 200 messages arrived despite the token rotation
omsentinel_get_data
seq_check 0 199

# Also verify the server issued more than one token
token_count=$(curl -s --cacert "$SENTINEL_CERT" \
    "https://127.0.0.1:${OMSENTINEL_PORT}/test/stats" \
    | $PYTHON -c "import json,sys; print(json.load(sys.stdin)['issued'])")
if [ -z "$token_count" ] || [ "$token_count" -lt 2 ]; then
    echo "FAIL: expected at least 2 token issuances, got '$token_count'"
    error_exit 1
fi

omsentinel_stop_server
echo "Token refresh verified: $token_count tokens issued"

exit_test
