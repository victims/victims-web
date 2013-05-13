#! /usr/bin/env bash

function usage()
{
	echo "USAGE: $0 <start|stop|restart]>"
	exit 1
}

if [ $# -ne 1 ]; then
	usage
fi
ARG=$1

BASE=$(dirname $(dirname $0))
TEST_DBPATH=$BASE/testdb
LOGFILE=$TEST_DBPATH/victims.mongo.log
LOCKFILE="${TEST_DBPATH}/mongod.lock"

function start()
{
	if [ ! -f "${LOCKFILE}" ]; then
		if [ ! -d "${TEST_DBPATH}" ]; then
			mkdir -p "${TEST_DBPATH}"
			NEW="new"
		fi
		nohup mongod --logpath "${LOGFILE}"  --dbpath "${TEST_DBPATH}" >> /dev/null 2>&1 &
		echo "Waiting for mongodb to be ready..."
		sleep 1
		while true; do
			match=$(grep -m 1 "waiting for connections on port" "${LOGFILE}")
			if [ ! -z "$match" ]; then
				if [ ! -z $NEW ]; then
					mongoimport -d victims -c hashes "$BASE/test/mongo_test.json"
				fi
				break;
			else
				match=$(grep -m 1 "dbexit" "${LOGFILE}")
				if [ ! -z "$match" ]; then
					echo "ERROR starting database"
					if [ ! -z $NEW ]; then
						cat ${LOGFILE}
						rm -rf ${TEST_DBPATH}
					fi
					break;
				else
					sleep 2
				fi
			fi
		done
		echo "Data: ${TEST_DBPATH}, Log: ${LOGFILE}"
	else
		echo "Datase already running"
	fi
}

function stop()
{
		mongod --shutdown --dbpath "${TEST_DBPATH}"
		rm -f "${LOCKFILE}"
}

case "$ARG" in
    "start" )
        start ;;
    "stop" )
        stop ;;
    "restart" )
    	stop; start ;;
    * )
    	echo "Invalid argument."; usage ;;
esac
