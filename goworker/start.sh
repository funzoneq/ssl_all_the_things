#!/bin/bash

/usr/bin/go build getcerts.go

for i in {1..5}
do
	./getcerts &
	sleep 2
done