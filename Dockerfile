FROM debian:jessie

RUN apt-get -y update
RUN apt-get -y install build-essential libssl-dev
# COPY / /src
# WORKDIR /src
# CMD make
