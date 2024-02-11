ARG BUILD_FROM
FROM $BUILD_FROM

MAINTAINER ROBOT0-VT <https://twitch.tv/ROBOT0-VT>

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV LANG C.UTF-8

RUN apk update && \
apk add --no-cache hostapd networkmanager-cli net-tools dnsmasq iptables

COPY hostapd.conf /
COPY dnsmasq.conf /

COPY run.sh /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
