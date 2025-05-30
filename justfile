set dotenv-load  # load env variables from .env

_default:
  @ just --list --unsorted

run:
  uv run main.py

build:
  uv run setup.py py2app -A

format-fix:
  uv tool run black .

format-check:
  uv tool run black . --check