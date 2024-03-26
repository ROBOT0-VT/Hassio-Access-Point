ARG BUILD_FROM
FROM $BUILD_FROM

MAINTAINER ROBOT0-VT <https://twitch.tv/ROBOT0-VT>

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV LANG C.UTF-8

RUN apk add --no-cache \
	iw \
	net-tools \
	hostapd \
	dnsmasq \
	iptables \
	avahi

COPY rootfs run.sh /

CMD [ "/run.sh" ]
