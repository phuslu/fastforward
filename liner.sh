#!/bin/sh
#
#       /etc/rc.d/init.d/liner
#
#       liner daemon
#
# chkconfig:   2345 95 05
# description: a liner script

### BEGIN INIT INFO
# Provides:       liner
# Required-Start:
# Required-Stop:
# Should-Start:
# Should-Stop:
# Default-Start: 2 3 4 5
# Default-Stop:  0 1 6
# Short-Description: liner
# Description: liner
### END INIT INFO

cd "$(dirname "$0")"

test -f .env && . $(pwd -P)/.env

_start() {
    test $(ulimit -n) -lt 100000 && ulimit -n 100000
    (env ENV=${ENV:-development} ./liner) <&- >liner.error.log 2>&1 &
    local pid=$!
    echo -n "Starting liner(${pid}): "
    sleep 1
    if (ps ax 2>/dev/null || ps) | grep "${pid} " >/dev/null 2>&1; then
        echo "OK"
    else
        echo "Failed"
    fi
}

_stop() {
    local pid="$(pidof liner)"
    if test -n "${pid}"; then
        echo -n "Stopping liner(${pid}): "
        if kill ${pid}; then
            echo "OK"
        else
            echo "Failed"
        fi
    fi
}

_restart() {
    if ! ./liner -validate ${ENV:-development}.yaml >/dev/null 2>&1; then
        echo "Cannot restart liner, please correct liner yaml file"
        echo "Run './liner -validate' for details"
        exit 1
    fi
    _stop
    sleep 1
    _start
}

_reload() {
    pkill -HUP -o -x liner
}

_usage() {
    echo "Usage: [sudo] $(basename "$0") {start|stop|reload|restart}" >&2
    exit 1
}

_${1:-usage}
