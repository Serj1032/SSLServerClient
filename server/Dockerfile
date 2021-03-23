FROM ubuntu:18.04

ARG UNAME=user
ARG UID=1000
ARG GID=1000

# https://habr.com/ru/post/448480/

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y cmake && \
    apt-get install -y apt-utils zlib1g-dev curl && \
    apt-get install -y g++ make binutils cmake libssl-dev libboost-all-dev && \
    apt-get install -y git libcurl4-openssl-dev ccache

RUN groupadd -g $GID -o $UNAME
RUN useradd -m -u $UID -g $GID -o -s /bin/bash $UNAME
USER $UNAME