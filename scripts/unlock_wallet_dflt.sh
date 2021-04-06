#!/bin/bash
PWD="PW5K7upq5PXibMsJxcbDksMPjRnjgtdLBKcSvy3P3cefwNjCQUZHH"
CLEOS=/mnt/disk/epid/cleos.sh

$CLEOS wallet open
$CLEOS wallet unlock --password $PWD
