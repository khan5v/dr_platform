# Marks generator/ as a regular package so `python -m generator.main` works.
# Without this file, the -m flag can't resolve the dotted module path and
# Python treats the directory as a namespace package (no __main__ support).
