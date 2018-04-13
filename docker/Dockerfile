FROM ubuntu:16.04

MAINTAINER zhaoyiyong zhaoyy1010@gmail.com

# data
RUN mkdir -p /bco
VOLUME /bco/data

WORKDIR /bco

# port
EXPOSE 8832 8833

# run
ADD ./bco/bin/bcod /usr/local/bin/
ADD ./bco/bin/bco-cli /usr/local/bin/
ADD ./bco/lib/ /usr/local/lib/

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]