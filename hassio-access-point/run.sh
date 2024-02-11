#!/usr/bin/with-contenv bashio

# SIGTERM-handler: this function will be executed when the container receives the SIGTERM signal (when stopping)
term_handler(){
	logger "Stopping Hass.io Access Point" 0
    nmcli -t dev set $INTERFACE managed yes
	ip link set $INTERFACE down
	ip addr flush dev $INTERFACE
	exit 0
}

# Logging function to set verbosity of output to addon log
logger(){
    msg=$1
    level=$2
    if [ $DEBUG -ge $level ]; then
        echo $msg
    fi
}

CONFIG_PATH=/data/options.json

# Convert integer configs to boolean, to avoid a breaking old configs
declare -r bool_configs=( hide_ssid client_internet_access dhcp )
for i in $bool_configs ; do
    if bashio::config.true $i || bashio::config.false $i ; then
        continue
    elif [ $config_value -eq 0 ] ; then
        bashio::addon.option $config_value false
    else
        bashio::addon.option $config_value true
    fi
done

SSID=$(bashio::config "ssid")
WPA_PASSPHRASE=$(bashio::config "wpa_passphrase")
CHANNEL=$(bashio::config "channel")
ADDRESS=$(bashio::config "address")
NETMASK=$(bashio::config "netmask")
BROADCAST=$(bashio::config "broadcast")
INTERFACE=$(bashio::config "interface")
HIDE_SSID=$(bashio::config.false "hide_ssid"; echo $?)
DHCP=$(bashio::config.false "dhcp"; echo $?)
DHCP_START_ADDR=$(bashio::config "dhcp_start_addr" )
DHCP_END_ADDR=$(bashio::config "dhcp_end_addr" )
DNSMASQ_CONFIG_OVERRIDE=$(bashio::config 'dnsmasq_config_override' )
DEBUG=$(bashio::config 'debug' )
HOSTAPD_CONFIG_OVERRIDE=$(bashio::config 'hostapd_config_override' )
CLIENT_INTERNET_ACCESS=$(bashio::config.false 'client_internet_access'; echo $?)
CLIENT_DNS_OVERRIDE=$(bashio::config 'client_dns_override' )
DNSMASQ_CONFIG_OVERRIDE=$(bashio::config 'dnsmasq_config_override' )

# Get the Default Route interface
DEFAULT_ROUTE_INTERFACE=$(bashio::network.name)

echo "Starting Hass.io Access Point Addon"

logger "Run command: nmcli dev set $INTERFACE managed no" 1
nmcli -t dev set $INTERFACE managed no

# Setup signal handlers
trap 'term_handler' SIGTERM

# Enforces required env variables
required_vars=(ssid wpa_passphrase channel address netmask broadcast)
for required_var in $required_vars; do
    bashio::config.require $required_var "An AP cannot be created without this information"
done

if [ ${#WPA_PASSPHRASE} -lt 8 ] ; then
    bashio::exit.nok "The WPA password must be at least 8 characters long!"
fi

# Setup hostapd.conf
logger "# Setup hostapd:" 1
logger "Add to hostapd.conf: ssid=$(bashio::config ssid)" 1
echo "ssid=$(bashio::config ssid)" >> /hostapd.conf
logger "Add to hostapd.conf: wpa_passphrase=********" 1
echo "wpa_passphrase=$(bashio::config wpa_passphrase)" >> /hostapd.conf
logger "Add to hostapd.conf: channel=$(bashio::config channel)" 1
echo "channel=$(bashio::config channel)" >> /hostapd.conf
logger "Add to hostapd.conf: ignore_broadcast_ssid=$(bashio::var.false HIDE_SSID)$?" 1
echo "ignore_broadcast_ssid=$(bashio::var.false HIDE_SSID)$?" >> /hostapd.conf

### MAC address filtering
## Allow is more restrictive, so we prioritise that and set
## macaddr_acl to 1, and add allowed MAC addresses to hostapd.allow
if bashio::config.has_value allow_mac_addresses ; then
    logger "Add to hostapd.conf: macaddr_acl=1" 1
    echo "macaddr_acl=1" >> /hostapd.conf
    logger "# Setup hostapd.allow:" 1
    logger "Allowed MAC addresses:" 0
    for mac in $(bashio::config allow_mac_addresses); do
        echo $mac >> /hostapd.allow
        logger $mac 0
    done
    logger "Add to hostapd.conf: accept_mac_file=/hostapd.allow" 1
    echo "accept_mac_file=/hostapd.allow"$'\n' >> /hostapd.conf
## else set macaddr_acl to 0, and add denied MAC addresses to hostapd.deny
elif bashio::config.has_value deny_mac_addresses; then
    logger "Add to hostapd.conf: macaddr_acl=0" 1
    echo "macaddr_acl=0" >> /hostapd.conf
    logger "Denied MAC addresses:" 0
    for mac in $(bashio::config deny_mac_addresses); do
        echo "$mac" >> /hostapd.deny
        logger "$mac" 0
    done
    logger "Add to hostapd.conf: accept_mac_file=/hostapd.deny" 1
    echo "deny_mac_file=/hostapd.deny" >> /hostapd.conf
## else set macaddr_acl to 0, with blank allow and deny files
else
    logger "Add to hostapd.conf: macaddr_acl=0" 1
    echo "macaddr_acl=0" >> /hostapd.conf
fi

# Set address for the selected interface. This replaces the old `/etc/network/interfaces` mechanism
ip address flush dev $INTERFACE
ip address add $(bashio::config address)/$(bashio::config netmask) dev $INTERFACE #broadcast
#ip link set $INTERFACE up

# Add interface to hostapd.conf
logger "Add to hostapd.conf: interface=$INTERFACE" 1
echo "interface=$INTERFACE" >> /hostapd.conf

# Append override options to hostapd.conf
if bashio::config.has_value hostapd_config_override; then
    logger "# Custom hostapd config options:" 0
    for override in $(bashio::config hostapd_config_override); do
        echo $override >> /hostapd.conf
        logger "Add to hostapd.conf: $override" 0
    done
fi

# Setup dnsmasq.conf if DHCP is enabled in config
if $(bashio::config.true "dhcp"); then
    logger "# DHCP enabled. Setup dnsmasq:" 1
    logger "Add to dnsmasq.conf: dhcp-range=$DHCP_START_ADDR,$DHCP_END_ADDR,12h" 1
        echo "dhcp-range=$DHCP_START_ADDR,$DHCP_END_ADDR,12h" >> /dnsmasq.conf
        logger "Add to dnsmasq.conf: interface=$INTERFACE" 1
        echo "interface=$INTERFACE" >> /dnsmasq.conf

    ## DNS
    if bashio::config.has_value client_dns_override; then
        dns_string="dhcp-option=6"
        for override in $CLIENT_DNS_OVERRIDE; do
            dns_string+=",$override"
        done
        echo $dns_string >> /dnsmasq.conf
        logger "Add custom DNS: $dns_string" 0
    else
        declare -a dns_array
        dns_array=$(bashio::dns.servers)

        if bashio::var.is_empty $dns_array; then
            bashio::config.suggest "client_dns_override" "The addon was unable to get the host's DNS servers."
        else
            dns_string="dhcp-option=6"
            for dns_entry in dns_array; do
                dns_string+=",$dns_entry"
            done
            echo $dns_string >> /dnsmasq.conf
            logger "Add DNS: $dns_string" 0
        fi
    fi

    # Append override options to dnsmasq.conf
    if bashio::var.has_value $DNSMASQ_CONFIG_OVERRIDE; then
        logger "# Custom dnsmasq config options:" 0
        for override in $DNSMASQ_CONFIG_OVERRIDE; do
            logger "Add to dnsmasq.conf: $override" 0
            echo "$override"$'\n' >> /dnsmasq.conf
        done
    fi
else
	logger "# DHCP not enabled. Skipping dnsmasq" 1
fi

# Setup Client Internet Access
if $(bashio::config.true "client_internet_access"); then

    ## Route traffic
    iptables-nft -t nat -A POSTROUTING -o $DEFAULT_ROUTE_INTERFACE -j MASQUERADE
    iptables-nft -P FORWARD ACCEPT
    iptables-nft -F FORWARD
fi

# Start dnsmasq if DHCP is enabled in config
if $(bashio::config.true "dhcp"); then
    logger "## Starting dnsmasq daemon" 1
    dnsmasq -C /dnsmasq.conf
fi

logger "## Starting hostapd daemon" 1
# If debug level is greater than 1, start hostapd in debug mode
if [ $DEBUG -gt 1 ]; then
    hostapd -d /hostapd.conf & wait ${!}
else
    hostapd /hostapd.conf & wait ${!}
fi
