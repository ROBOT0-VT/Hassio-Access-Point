#!/usr/bin/with-contenv bashio

DNSMASQ_CONFIG=/etc/dnsmasq.conf
HOSTAPD_CONFIG=/etc/hostapd.conf
WIRELESS_INTERFACE=$(bashio::config interface)
VIRTUAL_INTERFACE=hassioap-$WIRELESS_INTERFACE

# SIGTERM-handler: this function will be executed when the container receives the SIGTERM signal (when stopping)
term_handler(){
	bashio::log.notice "Stopping Hass.io Access Point"
    iw dev "$VIRTUAL_INTERFACE" del
	exit 0
}

# Remove old `debug` config option
if bashio::config.exists debug; then bashio::addon.option debug;fi

# Convert integer configs to boolean, to avoid a breaking old configs
for i in hide_ssid client_internet_access dhcp ; do
    if bashio::config.true "$i" || bashio::config.false "$i" ; then
        continue
    elif [ $i -eq 0 ] ; then
        bashio::addon.option $i false
    else
        bashio::addon.option $i true
    fi
done

# Enforces required env variables
for required_var in ssid wpa_passphrase channel address netmask; do
    bashio::config.require "$required_var" "An AP cannot be created without this information"
done
if [ "$(bashio::config wpa_passphrase | wc -m)" -lt 8 ] ; then
    bashio::exit.nok "The WPA password must be at least 8 characters long!"
fi

# Set log level from config
bashio::log.level "$(bashio::config log_level)"

# Setup signal handlers
trap 'term_handler' SIGTERMd

bashio::log.notice "Starting Hass.io Access Point Addon"

bashio::log.info "Creating virtual interface $VIRTUAL_INTERFACE..."
ip link set dev "$WIRELESS_INTERFACE" down
iw dev "$WIRELESS_INTERFACE" interface add "$VIRTUAL_INTERFACE" type __ap
HARDWARE_MAC=$(bashio::network.interface "network.interface.$WIRELESS_INTERFACE.mac" "$WIRELESS_INTERFACE" ".mac")

#MAC is a hash based on the original interface's MAC address, so it will always be the same for the same hardware
VIRTUAL_MAC=$(echo "hassio-access-point $HARDWARE_MAC" |md5sum|sed 's/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/')

bashio::log.info "Assigning the new interface $VIRTUAL_INTERFACE the following mac address: $VIRTUAL_MAC"
ip link set dev "$VIRTUAL_INTERFACE" address "$VIRTUAL_MAC"
if bashio::config.exists broadcast; then
    ip address add "$(bashio::config address)/$(bashio::config netmask)" dev "$VIRTUAL_INTERFACE" broadcast "$(bashio::config broadcast)"
else
    ip address add "$(bashio::config address)/$(bashio::config netmask)" dev "$VIRTUAL_INTERFACE"
fi
ip link set dev "$WIRELESS_INTERFACE" up

# Setup hostapd.conf
bashio::log.debug "Setting up hostapd:"
bashio::log.debug "Add to hostapd.conf: ssid=$(bashio::config ssid)"
echo "ssid=$(bashio::config ssid)" >> $HOSTAPD_CONFIG
bashio::log.debug "Add to hostapd.conf: wpa_passphrase=********"
echo "wpa_passphrase=$(bashio::config wpa_passphrase)" >> $HOSTAPD_CONFIG
bashio::log.debug "Add to hostapd.conf: channel=$(bashio::config channel)"
echo "channel=$(bashio::config channel)" >> $HOSTAPD_CONFIG
bashio::log.debug "Add to hostapd.conf: ignore_broadcast_ssid=$(bashio::var.false hide_ssid)$?"
echo "ignore_broadcast_ssid=$(bashio::var.false hide_ssid)$?" >> $HOSTAPD_CONFIG

### MAC address filtering
## Allow is more restrictive, so we prioritise that and set
## macaddr_acl to 1, and add allowed MAC addresses to hostapd.allow
if bashio::config.has_value allow_mac_addresses; then
    bashio::log.debug "Add to hostapd.conf: macaddr_acl=1"
    echo "macaddr_acl=1" >> /hostapd.conf
    bashio::log.debug "# Setup hostapd.allow:"
    bashio::config 'allow_mac_addresses|join("\n")' > /hostapd.allow
    bashio::log.info "Allowed MAC addresses:"
    bashio::log.info < /hostapd.allow
    # for mac in $(bashio::config allow_mac_addresses); do
    #     echo "$mac" >> /hostapd.allow
    #     bashio::log.info "   $mac"
    # done
    bashio::log.debug "Add to hostapd.conf: accept_mac_file=/hostapd.allow"
    echo "accept_mac_file=/hostapd.allow"$'\n' >> /hostapd.conf
## else set macaddr_acl to 0, and add denied MAC addresses to hostapd.deny
elif bashio::config.has_value deny_mac_addresses; then
    bashio::log.debug "Add to hostapd.conf: macaddr_acl=0"
    echo "macaddr_acl=0" >> /hostapd.conf
    bashio::log.info "Denied MAC addresses:"
    for mac in $(bashio::config deny_mac_addresses); do
        echo "$mac" >> /hostapd.deny
        bashio::log.info "$mac"
    done
    bashio::log.debug "Add to hostapd.conf: accept_mac_file=/hostapd.deny"
    echo "deny_mac_file=/hostapd.deny" >> /hostapd.conf
## else set macaddr_acl to 0, with blank allow and deny files
else
    bashio::log.debug "Add to hostapd.conf: macaddr_acl=0"
    echo "macaddr_acl=0" >> /hostapd.conf
fi

# Add interface to hostapd.conf
bashio::log.debug "Add to hostapd.conf: interface=$VIRTUAL_INTERFACE"
echo "interface=$VIRTUAL_INTERFACE" >> /hostapd.conf

# Append override options to hostapd.conf
if bashio::config.has_value hostapd_config_override; then
    bashio::log.info "# Custom hostapd config options:"
    for override in $(bashio::config hostapd_config_override); do
        echo "$override" >> /hostapd.conf
        bashio::log.info "Add to hostapd.conf: $override"
    done
fi

# Setup dnsmasq.conf if DHCP is enabled in config
if bashio::config.true dhcp; then
    bashio::log.debug "# DHCP enabled. Setup dnsmasq:"
    bashio::log.debug "Add to dnsmasq.conf: dhcp-range=$(bashio::config dhcp_start_addr),$(bashio::config dhcp_end_addr),12h"
    echo "dhcp-range=$(bashio::config dhcp_start_addr),$(bashio::config dhcp_end_addr),12h" >> $DNSMASQ_CONFIG
    bashio::log.debug "Add to dnsmasq.conf: interface=$VIRTUAL_INTERFACE"
    echo "interface=$VIRTUAL_INTERFACE" >> $DNSMASQ_CONFIG

    ## DNS
    dns_option="dhcp-option=6,"
    if bashio::config.has_value client_dns_override; then
        echo "$dns_option+$(bashio::config 'client_dns_override|join(",")')" \
            >> $DNSMASQ_CONFIG
        bashio::log.info "Add custom DNS: $dns_string"
    else
        dns_string="dhcp-option=6,$(bashio::dns.host)"
        echo "$dns_string" >> $DNSMASQ_CONFIG
        bashio::log.info "Using Home Assistant as the DNS server"
    fi

    # Append override options to dnsmasq.conf
    if bashio::config.has_value dnsmasq_config_override; then
        bashio::log.info "Custom dnsmasq config options:"
        for override in $(bashio::config dnsmasq_config_override); do
            bashio::log.info "Add to dnsmasq.conf: $override"
            echo "$override" >> $DNSMASQ_CONFIG
        done
    fi
else
	bashio::log.debug "DHCP not enabled. Skipping dnsmasq"
fi

# Configure routing
bashio::log.debug "Setting up firewall rules"

iptables-nft -i "$VIRTUAL_INTERFACE" -t nat -A POSTROUTING -o "$(bashio::network.name)" -j MASQUERADE

# Setup Client Internet Access
if bashio::config.true client_internet_access; then
    bashio::log.debug "Changing routing to allow internet access"
    ## Route traffic
    iptables-nft -i "$VIRTUAL_INTERFACE" -P FORWARD ACCEPT
    iptables-nft -i "$VIRTUAL_INTERFACE" -F FORWARD
fi

# Start dnsmasq if DHCP is enabled in config
if bashio::config.true dhcp; then
    bashio::log.debug "Starting dnsmasq daemon"
    dnsmasq
fi

bashio::log.debug "Starting hostapd daemon"
# If debug level is DEBUG or greater, start hostapd in debug mode
if [ "$__BASHIO_LOG_LEVEL" -gt 6 ]; then
    hostapd -d /hostapd.conf & wait ${!}
else
    hostapd /hostapd.conf & wait ${!}
fi
