NAME = xiexianbin/pebble
VERSION = 1

.PHONY: build tag-latest

build:  build-version

build-version:
	docker build -t ${NAME}:${VERSION} -f docker/pebble/linux.Dockerfile .

tag-latest:
	docker tag ${NAME}:${VERSION} ${NAME}:latest

push:   build-version tag-latest
	docker push ${NAME}:${VERSION}; docker push ${NAME}:latest
