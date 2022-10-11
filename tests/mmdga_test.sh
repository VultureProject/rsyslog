#!/bin/bash
# released under ASL 2.0
# export USE_VALGRIND="YES"
. ${srcdir:=.}/diag.sh init
generate_conf

add_conf '
template(name="dga-output" type="list") {
  property(name="$!all-json")
}

module(load="../plugins/imptcp/.libs/imptcp")
module(load="../plugins/mmjsonparse/.libs/mmjsonparse")
module(load="../contrib/mmdga/.libs/mmdga")
input(type="imptcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port" ruleset="testing")

ruleset(name="testing" queue.workerThreads="4") {
    action(type="mmjsonparse" cookie="")
    action(type="mmdga" model_path="/workspaces/rsyslog/dga_model/dga_model.tflite" 
                        domain_input_field="$!domain" 
                        score_output_field="!dga_score"
                        cache_size="1000")
    action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="dga-output")
}
'
# ruleset options:
# queue.workerThreads="1"
# queue.workerThreads="5" queue.workerThreadMinimumMessages="1000"


# uncomment for debugging support:
# export RSYSLOG_DEBUG="debug"
# export RSYSLOG_DEBUGLOG="log"

 startup
tcpflood -I '/workspaces/rsyslog/dga_model/extract.json'
shutdown_when_empty
wait_shutdown
content_check --regex '"dga_score": 0.' # it should match the saved certitude

exit_test
