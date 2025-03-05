#!/bin/bash

######################################
#         Setting Variables          #
######################################
INPUT_FILENAME=$1
NEW_GAMESERVER_URL=$2
NEW_DLCSERVER_URL=$3

export DLC_URL="${NEW_DLCSERVER_URL}"
export SOURCE_OUTPUT="tappedout"

if [ -z "${INPUT_FILENAME}" ] || [ -z "${NEW_GAMESERVER_URL}" ] ||  [ -z "${NEW_DLCSERVER_URL}" ]; then
    echo "Usage:" $0 "[INPUT_FILENAME] [NEW_GAMESERVER_URL] [NEW_DLCSERVER_URL]"
    exit 1
fi

######################################
#      Installing Dependencies       #
######################################
if ! [ -f apktool_2.10.0.jar ]; then
	curl -Lo apktool_2.10.0.jar https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar
fi

if ! [ -f venv/bin/pip ]; then
	python3 -m venv venv
	if [ ! $? -eq 0 ]; then
	    exit 1 
	fi

	venv/bin/pip install buildapp && venv/bin/buildapp_fetch_tools
	if [ ! $? -eq 0 ]; then
	    exit 1
	fi

	venv/bin/pip install r2pipe
	if [ ! $? -eq 0 ]; then
	    exit 1
	fi
fi

######################################
#           Decompile App            #
######################################
java -jar apktool_2.10.0.jar  d $INPUT_FILENAME -o tappedout

######################################
#         Change Server Urls         #
######################################

grep -rl "https://prod.simpsons-ea.com" ./tappedout/ 	| xargs -r sed -i "s|https://prod.simpsons-ea.com|${NEW_GAMESERVER_URL}|g" 	# Gameserver 

grep -rl "https://syn-dir.sn.eamobile.com" ./tappedout/ | xargs -r sed -i "s|https://syn-dir.sn.eamobile.com|${NEW_GAMESERVER_URL}|g" 	# Director Api Url

grep -rl "https://oct2018-4-35-0-uam5h44a.tstodlc.eamobile.com/netstorage/gameasset/direct/simpsons/" ./tappedout/ | xargs -r sed -i "s|https://oct2018-4-35-0-uam5h44a.tstodlc.eamobile.com/netstorage/gameasset/direct/simpsons/|${NEW_DLCSERVER_URL}|g" # DLC Server
venv/bin/python3 patch_native.py # DLC Server

######################################
#           Recompile App            #
######################################
venv/bin/buildapp -d tappedout -o "$(basename $INPUT_FILENAME .apk)-patched.apk"
