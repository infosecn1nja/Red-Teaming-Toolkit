#!/bin/bash

cat README.md |grep "https://github.com/" |cut -d":" -f2 |cut -d" " -f1 > tools.txt &&

cat tools.txt | cut -d"/" -f3,4,5,6,7,8,9,10 > tools2.txt &&

rm -rf tools.txt &&
mv tools2.txt tools.txt &&

echo 'Starting...'

for tool in $(cat tools.txt); do
    git clone https://$tool
done
