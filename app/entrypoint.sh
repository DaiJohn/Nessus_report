#!/bin/bash
set -e

#1️⃣ Create log folder and cron.log file
mkdir -p /logs
touch /logs/cron.log

#2️⃣ Export container environment variables to cron
#    Note the correct path /etc/environment
env > /etc/environment

#3️⃣ Start cron daemon
cron

#4️⃣ Keep container running in foreground to view logs
tail -f /logs/cron.log