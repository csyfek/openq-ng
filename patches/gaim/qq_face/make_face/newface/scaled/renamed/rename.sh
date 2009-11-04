#!/bin/bash

for i in ./*.png
do
	mv $i ${i%.a.png}.png
done

#num=1
#while [ $num -lt 101 ]
#do
#	cp $num.png qq_$num-1.png
#	let num+=1
#done

#mkdir -p upload && mv qq* upload
#
echo "\nDone!"

#convert -transparent "#c7e4ff" 1.bmp 1_1.png
