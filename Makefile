all:
	make back

front:
	NODE_ENV=production npm run build

back:
	go install -ldflags "-X github.com/mickael-kerjean/filestash/server/common.BUILD_DATE=`date -u +%Y%m%d` -X github.com/mickael-kerjean/filestash/server/common.BUILD_REF=`git rev-parse HEAD`" ./...
