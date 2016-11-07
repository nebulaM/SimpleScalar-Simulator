#!/bin/bash
cp ./$1/sim-safe.c /home//Documents/CPEN411/"sim-cpen411-$1" || echo "unable to copy file to $"
#cp sim-scalar-cpen411.c /home//Documents/CPEN411/sim-cpen411-a2 || echo "unable to copy to a2"
cd /home//Documents/CPEN411/ && bash run $1 && cd /media/sf_CPEN411/assign