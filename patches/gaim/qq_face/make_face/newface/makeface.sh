#!/bin/bash

for i in ./*.bmp
do
	convert -transparent "#c7e4ff" $i ${i%.bmp}.png
done

num=1
while [ $num -lt 101 ]
do
	cp $num.png qq_$num-1.png
	let num+=1
done

mkdir -p upload && mv qq* upload

echo "\nDone!"

#convert -transparent "#c7e4ff" 1.bmp 1_1.png

######
#num=1
#while [ $num -lt 101 ]
#do
#	mv qq_$num-1.png qq_${num}-2.png
#	let num+=1
#done

