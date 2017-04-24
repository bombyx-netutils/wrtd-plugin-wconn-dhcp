#!/bin/bash

LIBFILES="$(find ./wconn_dhcp -name '*.py' | tr '\n' ' ')"

autopep8 -ia --ignore=E501 ${LIBFILES}
