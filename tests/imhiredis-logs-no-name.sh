#!/usr/bin/env bash
# added 2025-11-20 by Théo Bertin, released under ASL 2.0
## Uncomment for debugging
#export RS_REDIR=-d

. ${srcdir:=.}/diag.sh init

start_redis

generate_conf
add_conf '
global(localhostname="server")
module(load="../contrib/imhiredis/.libs/imhiredis")

template(name="outfmt" type="string" string="%$/num% %msg%\n")

input(type="imhiredis"
        server="127.0.0.1"
        port="'$REDIS_RANDOM_PORT'"
        key="mykey"
        mode="queue"
        ruleset="redis")

ruleset(name="redis") {
  set $/num = cnum($/num + 1);
  action(type="omfile"
            file="'$RSYSLOG_OUT_LOG'"
            template="outfmt")
}

action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
startup
shutdown_when_empty
wait_shutdown

stop_redis

content_check "imhiredis[(null)]: "
check_not_present "imhiredis: "

# Removes generated configuration file, log and pid files
cleanup_redis

exit_test
