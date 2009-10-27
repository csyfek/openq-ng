#!/bin/bash

i=1

while [ $i -lt 101 ]
do
	convert -monochrome qq_$i-1.png qq_$i-2.png
done

echo "done!"
