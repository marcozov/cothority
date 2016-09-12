#!/usr/bin/env bash

DBG_SHOW=1
# Debug-level for app
DBG_APP=2
DBG_SRV=0
# Uncomment to build in local dir
#STATICDIR=test
# Needs 4 clients
NBR=4

. lib/test/libtest.sh
. lib/test/cothorityd.sh

main(){
    startTest
    build
	test Build
	test Root
	test Config
    stopTest
}

testConfig(){
	testRoot
	testOK scmgr 1 pool $ID group2.toml
	testOK scmgr 2 pool vote -y $POOL
}

testRoot(){
	cothoritySetup 5 3
	testOK scmgr 1 root create group.toml
	testOK scmgr 2 root join $ID
	testOK scmgr 1 root vote -y $ID
}

testBuild(){
    testOK dbgRun ./scmgr --help
}

scmgr(){
    local D=tmpl$1
    shift
    dbgRun ./scmgr -d $DBG_APP sc$D -c $@
}

build(){
    BUILDDIR=$(pwd)
    if [ "$STATICDIR" ]; then
        DIR=$STATICDIR
    else
        DIR=$(mktemp -d)
    fi
    mkdir -p $DIR
    cd $DIR
    echo "Building in $DIR"
    for app in scmgr; do
        if [ ! -e $app -o "$BUILD" ]; then
            if ! go build -o $app $BUILDDIR/$app/*.go; then
                fail "Couldn't build $app"
            fi
        fi
    done
    for sc in $(seq $NBR); do
    	rm -rf sc$sc
    	mkdir sc$sc
    done
}

if [ "$1" -a "$STATICDIR" ]; then
    rm -f $STATICDIR/{scmgr}
fi

main
