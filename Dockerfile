FROM alpine:latest

RUN apk add --update \
    python3

ENV LIBRARY_PATH=/lib:/usr/lib

WORKDIR /crouter
ADD . /crouter


CMD ./setup.sh