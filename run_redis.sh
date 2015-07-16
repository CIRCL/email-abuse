#!/bin/bash

set -e
set -x

REDIS_HOME='/home/raphael/gits/redis/src'

${REDIS_HOME}/redis-server ./redis.conf

