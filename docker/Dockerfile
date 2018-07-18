FROM ubuntu:16.04

MAINTAINER zhaoyiyong zhaoyy1010@gmail.com

# data
RUN mkdir -p /btchd
VOLUME /btchd/data

WORKDIR /btchd

# port
EXPOSE 8832 8833

# run
ADD ./btchd/bin/btchdd /usr/local/bin/
ADD ./btchd/bin/btchd-cli /usr/local/bin/
ADD ./btchd/lib/ /usr/local/lib/

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]