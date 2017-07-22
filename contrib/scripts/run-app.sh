#! /usr/bin/env bash
# to be run in the dev environment

SCRIPT_DIR=$(dirname $0)

SRC_DIR=$(dirname "$SCRIPT_DIR")
while true; do
	if [ -d "${SRC_DIR}/src" ]; then
		SRC_DIR="${SRC_DIR}/src"
		break;
	elif [ "/" == "${SRC_DIR}" ]; then
		echo "Could not find test dirctory."
		exit 1
	fi
	SRC_DIR=$(dirname "${SRC_DIR}")
done

MONGOSH="$SCRIPT_DIR/mongo-db-ctl.sh"
APP="$SRC_DIR/web/application.py"

$MONGOSH stop
$MONGOSH start
python $APP
$MONGOSH stop
