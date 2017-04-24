#!/bin/bash

LIBFILES="$(find ./wconn_pppoe -name '*.py' | tr '\n' ' ')"

autopep8 -ia --ignore=E501 ${LIBFILES}
