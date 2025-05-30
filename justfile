set dotenv-load  # load env variables from .env

_default:
  @ just --list --unsorted

run:
  #!/bin/sh
  set -eu

  # # mac os setup
  # PYTHON_PATH=$(cd ~ && uv run which python)
  # BASE_PATH=$(dirname "$(dirname "$PYTHON_PATH")")
  # TCL_LIBRARY="$BASE_PATH/lib/tcl8.6"
  # TK_LIBRARY="$BASE_PATH/lib/tk8.6"
  # export TCL_LIBRARY
  # export TK_LIBRARY
  # # echo "TCL_LIBRARY has been set to: $TCL_LIBRARY"
  # # echo "TK_LIBRARY has been set to: $TK_LIBRARY"

  uv run main.py

build:
  uv run setup.py py2app -A