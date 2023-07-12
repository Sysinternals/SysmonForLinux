#!/bin/bash
process_name="t4"

# Wait enough time for it to get into hung state
sleep 20m
counter=1
while [ $counter -le 20 ]
do
    if pgrep -x "$process_name" > /dev/null; then
        echo "Process $process_name is running. Dumping stacks..."
        process_id=$(pgrep -x "$process_name")
        dotnet-stack report -p "$process_id"
        echo "Stacks dumped"
    fi

    sleep 1m
    counter=$((counter + 1))
done