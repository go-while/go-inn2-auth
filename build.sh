#!/bin/bash
PATH="$PATH:/usr/local/go/bin"
export GOPATH=$(pwd)
go vet go-inn2-auth.go || exit 1
go fmt go-inn2-auth.go
go build go-inn2-auth.go
RET=$?
echo $(date)
test $RET -gt 0 && echo "BUILD FAILED! RET=$RET" || echo "BUILD OK!"
ls -lh go-inn2-auth
exit $RET
