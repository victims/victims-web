# Usage: source <script>
# Switch to dev environment
# Sets up the development environment if it does not exist

ENV_PREFIX=victims
ENV_PYTHON=python
ENV_DIR=${ENV_PREFIX}.dev
ENV_PROMPT=${ENV_PREFIX}.dev

# We know pip is installed, so use it
CMD="pip install"

function initialize {
    $CMD "$(pwd)"
    $CMD coverage nose pep8 --use-mirrors
    $CMD -e . --use-mirrors
}

function vitualize {
    if [ ! -d "$ENV_DIR" ]; then
        virtualenv -p $(which ${ENV_PYTHON}) --prompt=${ENV_PROMPT} ${ENV_DIR}
        source ${ENV_DIR}/bin/activate
        initialize
    else
        source ${ENV_DIR}/bin/activate
    fi

    # Make sure we install any new dependencies
    $CMD -e . --upgrade --use-mirrors

    export PYTHONPATH=$PYTHONPATH:$(pwd)/src

}


# We require virtuaenv and (easy_install/pip) to be installed
{ command -v virtualenv >/dev/null 2>&1 && vitualize; } || { echo >&2 "ERROR: virtualenv command not found, not switching"; }

