#!/bin/bash
source bin/activate
source lab1-platform-openrc.sh
python novaintercept.py --upstream 10.3.16.15
