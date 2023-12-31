#!/bin/sh
rm -rf nsispack
mkdir nsispack
copypedeps nlamagent.exe nsispack
cp README nsispack
cp LICENSE nsispack
