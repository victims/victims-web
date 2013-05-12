#! /usr/bin/env bash
# to be run in the dev environment

SCRIPT_DIR=$(dirname $0)

MONGOSH="$SCRIPT_DIR/mongo-db-ctl.sh"
# gracefully start db
bash "$MONGOSH" start

# execute tests
BASE=$(dirname "$SCRIPT_DIR")
python /usr/bin/nosetests --with-coverage --cover-package=victims_web --cover-min-percentage=0 -v ${BASE}/test/*.py

# stop db
bash "$MONGOSH" stop

