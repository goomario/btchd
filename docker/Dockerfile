FROM ubuntu:16.04

MAINTAINER btchd develop@btchd.org

# data
RUN mkdir -p /btchd
VOLUME /btchd/data

WORKDIR /btchd

# port
EXPOSE 8732 8833

# run
ADD /btchd /btchd

COPY docker-entrypoint.sh /btchd/
RUN chmod +x /btchd/docker-entrypoint.sh

ENTRYPOINT ["/btchd/docker-entrypoint.sh"]