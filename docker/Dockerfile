FROM ubuntu:16.04

MAINTAINER zhaoyiyong zhaoyy1010@gmail.com

# env
RUN apt-get update && \
    apt-get install -y build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils python3


RUN apt-get install -y libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev

RUN apt-get install -y software-properties-common && \
        add-apt-repository -y ppa:bitcoin/bitcoin && \
        apt-get update && \
        apt-get install -y libdb4.8-dev libdb4.8++-dev

RUN apt-get install -y libminiupnpc-dev
RUN apt-get install -y libzmq3-dev

RUN apt-get clean

# data
RUN mkdir -p /bco
VOLUME /bco/data
VOLUME /bco/dev

WORKDIR /bco

# port
EXPOSE 8332 8333 18332 18333

# run
ADD bcod /usr/local/bin/
ADD bco-cli /usr/local/bin/

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]