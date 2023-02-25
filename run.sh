#!/usr/bin/env bash
# set -x




_usage() {
	echo "Could not find config file."
	echo "Usage: $0 [/path/to/openwrt.conf]"
	exit 1
}

SCRIPT_DIR=$(cd $(dirname $0) && pwd )
DEFAULT_CONFIG_FILE=$SCRIPT_DIR/openwrt.conf
CONFIG_FILE=${1:-$DEFAULT_CONFIG_FILE}
source $CONFIG_FILE 2>/dev/null || { _usage; exit 1; }

_nmcli() {
	type nmcli >/dev/null 2>&1
	if [[ $? -eq 0 ]]; then
		echo "* setting interface '$WIFI_IFACE' to unmanaged"
		nmcli dev set $WIFI_IFACE managed no
		nmcli radio wifi on
	fi
}

_get_phy_from_dev() {
	test $WIFI_ENABLED = 'true' || return
	test -z $WIFI_PHY || return
	if [[ -f /sys/class/net/$WIFI_IFACE/phy80211/name ]]; then
		WIFI_PHY=$(cat /sys/class/net/$WIFI_IFACE/phy80211/name 2>/dev/null)
		echo "* got '$WIFI_PHY' for device '$WIFI_IFACE'"
	else
		echo "$WIFI_IFACE is not a valid phy80211 device"
		exit 1
	fi
}

_cleanup() {
	echo -e "\n* cleaning up..."
	echo "* stopping container"
	docker stop $CONTAINER >/dev/null
	echo "* cleaning up netns symlink"
	sudo rm -rf /var/run/netns/$CONTAINER
	echo "* removing host $LAN_DRIVER interface"
	if [[ $LAN_DRIVER != "bridge" ]] ; then
		sudo ip link del dev $LAN_IFACE
	elif [[ $LAN_PARENT =~ \. ]] ; then
		sudo ip link del dev $LAN_PARENT
	fi
	echo -ne "* finished"
}

_gen_config() {
	echo "* generating network config"
	set -a
	_get_phy_from_dev
	source $CONFIG_FILE
	for file in etc/config/*.tpl; do
		envsubst <${file} >${file%.tpl}
		docker cp ${file%.tpl} $CONTAINER:/${file%.tpl}
	done
	set +a
}

_init_network() {
	echo "* setting up docker network"
	local LAN_ARGS
	case $LAN_DRIVER in
		bridge)
			LAN_ARGS=""
		;;
		macvlan)
			LAN_ARGS="-o parent=$LAN_PARENT"
		;;
		ipvlan)
			LAN_ARGS="-o parent=$LAN_PARENT -o ipvlan_mode=l2"
		;;
		*)
			echo "invalid choice for LAN network driver"
			exit 1
		;;
	esac
	docker network create --driver $LAN_DRIVER \
		$LAN_ARGS \
		--subnet $LAN_SUBNET \
		$LAN_NAME || exit 1

	docker network create --driver $WAN_DRIVER \
		-o parent=$WAN_PARENT \
		$WAN_NAME || exit 1
}

_set_hairpin() {
	test $WIFI_HAIRPIN = 'true' || return
	echo -n "* set hairpin mode on interface '$1'"
	for i in {1..10}; do
		echo -n '.'
		sudo ip netns exec $CONTAINER ip link set $WIFI_IFACE type bridge_slave hairpin on 2>/dev/null && { echo 'ok'; break; }
		sleep 3
	done
	if [[ $i -ge 10 ]]; then
		echo -e "\ncouldn't set hairpin mode, wifi clients will probably be unable to talk to each other"
	fi
}

_create_or_start_container() {
	if ! docker inspect $IMAGE:$TAG >/dev/null 2>&1; then
		echo "no image '$IMAGE:$TAG' found, did you forget to run 'make build'?"
		exit 1

	elif docker inspect $CONTAINER >/dev/null 2>&1; then
		echo "* starting container '$CONTAINER'"
		docker start $CONTAINER || exit 1

	else
		_init_network
		echo "* creating container $CONTAINER"
		docker create \
			--network $LAN_NAME \
			--cap-add NET_ADMIN \
			--cap-add NET_RAW \
			--hostname openwrt \
			--ip $LAN_ADDR \
			--sysctl net.netfilter.nf_conntrack_acct=1 \
			--sysctl net.ipv6.conf.all.disable_ipv6=0 \
			--sysctl net.ipv6.conf.all.forwarding=1 \
			--name $CONTAINER $IMAGE:$TAG >/dev/null
		docker network connect $WAN_NAME $CONTAINER

		_gen_config
		docker start $CONTAINER
	fi
}

_reload_fw() {
	echo "* reloading firewall rules"
	docker exec -i $CONTAINER sh -c '
		for iptables in iptables ip6tables; do
			for table in filter nat mangle; do
				$iptables -t $table -F
			done
		done
		/sbin/fw3 -q restart'
}

_prepare_wifi() {
	test $WIFI_ENABLED = 'true' || return
	test -z $WIFI_IFACE && _usage
	_get_phy_from_dev
	_nmcli
	echo "* moving device $WIFI_PHY to docker network namespace"
	sudo iw phy "$WIFI_PHY" set netns $pid
	_set_hairpin $WIFI_IFACE
}

_prepare_network() {
	case $LAN_DRIVER in
		macvlan)
			echo "* setting up host $LAN_DRIVER interface"
			LAN_IFACE=macvlan0
			sudo ip link add $LAN_IFACE link $LAN_PARENT type $LAN_DRIVER mode bridge
			sudo ip link set $LAN_IFACE up
			sudo ip route add $LAN_SUBNET dev $LAN_IFACE
		;;
		ipvlan)
			echo "* setting up host $LAN_DRIVER interface"
			LAN_IFACE=ipvlan0
			sudo ip link add $LAN_IFACE link $LAN_PARENT type $LAN_DRIVER mode l2
			sudo ip link set $LAN_IFACE up
			sudo ip route add $LAN_SUBNET dev $LAN_IFACE
		;;
		bridge)
			LAN_ID=$(docker network inspect $LAN_NAME -f "{{.Id}}")
			LAN_IFACE=br-${LAN_ID:0:12}

			# test if $LAN_PARENT is a VLAN of $WAN_PARENT, create it if it doesn't exist and add it to the bridge
			local lan_array=(${LAN_PARENT//./ })
			if [[ ${lan_array[0]} = $WAN_PARENT ]] && ! ip link show $LAN_PARENT >/dev/null 2>&1 ; then
				sudo ip link add link ${lan_array[0]} name $LAN_PARENT type vlan id ${lan_array[1]}
			fi
			sudo ip link set $LAN_PARENT master $LAN_IFACE
		;;
		*)
			echo "invalid network driver type, must be 'bridge' or 'macvlan'"
			exit 1
		;;
	esac

	if [[ "${WAN_DRIVER}" = "ipvlan" ]] ; then
		echo "* 'ipvlan' mode selected for WAN interface"
		# need to set DHCP broadcast flag
		# and set clientid to some random value so we get a new lease
		# https://tools.ietf.org/html/rfc1542#section-3.1.1
		local client_id
		client_id=$(tr -dc 'A-F0-9' < /dev/urandom | head -c12)
		docker exec -it $CONTAINER sh -c "
			uci -q set network.wan.broadcast=1
			uci -q set network.wan.clientid=${client_id}
			uci commit"
	fi

	echo "* getting address via DHCP"
	sudo dhcpcd -q $LAN_IFACE
}



#reload radio
_reload_radio() {
	      echo "* reloading radio rules"
		docker exec -i $CONTAINER /sbin/wifi down radio0 
		sleep 2;
		docker exec -i $CONTAINER /sbin/wifi up radio0
		
}



#Monitor container to exit for restart systemd to take effect of restartalways flag
monitor_restart_container() {
	local  LISTJOBS=$1
	while true; do
		RUNNING=$(docker inspect --format="{{ .State.Running }}" $CONTAINER)
		if [ "$RUNNING" == "false" ]; then
			 echo "$CONTAINER $RUNNING is not running. Sleep for 1 second exiting" 
			 	for pid in $LISTJOBS; do kill -9 $pid ; done ; 
			 _cleanup
			 ip li delete "$WIFI_PHY" 2>/dev/null
			 modprobe iwlwifi
			 modprobe -r iwlwifi
			 modprobe -r iwldvm
			 modprobe -r iwlwifi
			 modprobe iwlwifi
			 modprobe iwldvm
			 sleep 5
			exit 1;
		fi
		sleep 1
	done
}




#Monitor the parent eth0 if removed from the host and reinserted push it back to openwrt
monitor_parent_wan(){
	
#MAIN_ETH_MAC=`ip netns exec $CONTAINER ip link show eth1 | grep link/ether | awk '{print $2}'` 
#MAIN_ETH_MAC=$(docker network inspect $WAN_NAME -f "{{.Containers}}"  | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}')
	while true ; do
			if  ls /sys/class/net/ | grep -q $WAN_PARENT; then
				if ! docker exec -i $CONTAINER  ip a | grep -q -Eow 'eth1.*state UP';  then
                                        #ip netns exec $CONTAINER ip link delet
					#docker exec -i $CONTAINER  ip link set dev "eth1" down   
                    ip netns exec $CONTAINER ip link set dev "eth1" down 
					ip link add "eth1" link $WAN_PARENT type macvlan
					ip link set dev "eth1" promisc on
					ip link set "eth1" netns  $CONTAINER
					ip netns exec $CONTAINER ifconfig "eth1" up
					
					#sleep 1;
					_reload_fw
                                      # if [ ! -z "$MAIN_ETH_MAC" -a "$MAIN_ETH_MAC" != " " ]; then
				           #docker exec -i $CONTAINER  ip link set dev "eth1" down   
                                    #   ip netns exec $CONTAINER ip link set dev "eth1" down 
	                                #  ip netns exec $CONTAINER ip link set dev "eth1" address "$MAIN_ETH_MAC"
					   #ip netns exec $CONTAINER ifconfig "eth1" up
                                          # echo "$MAIN_ETH_MAC";
                                      # fi
					#ip netns exec $CONTAINER ifconfig "eth1" up
					#sleep `/usr/bin/shuf -i 5-10 -n 1`;
                                        #_reload_fw
					#docker exec -i $CONTAINER /etc/init.d/mwan3 restart
				fi
#			else
#				echo "$WAN_PARENT not linked"
			fi
		
		sleep 5;
	done
	
}



add_mwan3(){
# https://gist.github.com/braian87b/97a186b2e11b5aa438d8fd17de0eab20
# 	uci set firewall.@zone[0].conntrack='1'
# uci set firewall.@zone[1].conntrack='1'
# uci commit
# sync
# reboot


	# add interface to mwan3

if !  docker exec -i $CONTAINER sh -c 'cat /etc/config/mwan3' | grep -q "config interface '$ethnetnamed'"; then

echo "* configure mwan3 interface '$ethnetnamed'"
docker exec -i $CONTAINER sh -c "cat << EOF >> /etc/config/mwan3
 config member '$mwan3member'
	option interface '$ethnetnamed'
	option metric '1'
	option weight '1'
	
config interface '$ethnetnamed'
	option enabled '1'
	option initial_state 'online'
	option family 'ipv4'
	list track_ip '8.8.8.8'
	list track_ip '8.8.4.4'
	option track_method 'ping'
	option reliability '1'
	option count '1'
	option size '56'
	option max_ttl '60'
	option check_quality '0'
	option timeout '2'
	option interval '5'
	option failure_interval '5'
	option recovery_interval '5'
	option down '3'
	option up '3'
EOF"

# check if it's added to member of Network Balance
# if !  docker exec -i $CONTAINER sh -c 'cat /etc/config/mwan3' | grep -q "config policy 'Balance_Wan'.*\n.*list use_member '$mwan3member'"; then
echo "* creating mwan3 member load balance '$mwan3member'"
	docker exec -i $CONTAINER sed -i -E "s#option last_resort 'default'#list use_member '$mwan3member'\n\0#g" /etc/config/mwan3

# fi
# check if it's added to member of Network fallover
# if !  docker exec -i $CONTAINER sh -c 'cat /etc/config/mwan3'  | grep -q "config policy 'Fallover_Wan'.*\n.*list use_member '$mwan3member'"; then
echo "* creating mwan3 member fallover '$mwan3member'"
	docker exec -i $CONTAINER sed -i -E "s#option last_resort 'unreachable'#list use_member '$mwan3member'\n\0#g" /etc/config/mwan3

# fi

docker exec -i $CONTAINER sh -c '/etc/init.d/mwan3 reload';
_reload_fw
fi








}



# Add multi enthernet interface listed and constantly check if it's connected to the host if removed and reinserted move to the openwrt netns
add_multiple_wan(){
	while true ; do
		for multiwan in "${WAN_LIST[@]}"; do

         #Skip the main Wan
		if [ "$WAN_PARENT" == "$multiwan" ]; then
		continue
		fi

		indexwan=0
		constmetric=5
		
		indexwan=$(($indexwan+1))
		constmetric=$(($constmetric*2))
		ethnetnamed="multiwan$indexwan"
		zonename="multiwan$indexwan"
		mwan3member="M_W_$(($indexwan+1))"


			if  ls /sys/class/net/ | grep -q $multiwan; then
				if ! docker exec -i $CONTAINER  ip a | grep -q -Eow "$ethnetnamed.*state UP";  then
				echo "* adding interface $multiwan on host to netns named as '$ethnetnamed'"
                
				# pre cleanup
				ip link del dev $ethnetnamed 2>/dev/null
				ip netns exec $CONTAINER ip link set dev "$ethnetnamed" down  2>/dev/null
				ip netns exec $CONTAINER ip link del dev "$ethnetnamed" 2>/dev/null

				# add
				ip link add "$ethnetnamed" link "$multiwan" type macvlan
				# ip link set dev "$ethnetnamed" promisc on
				ip link set "$ethnetnamed" netns  $CONTAINER
				ip netns exec $CONTAINER ifconfig "$ethnetnamed" up
				#configure interface and add to wan zone

				if !  docker exec -i $CONTAINER sh -c 'cat /etc/config/network' | grep -q "option ifname '$ethnetnamed'"; then


#adding interface hard way but works
echo "* configuring interface $ethnetnamed on Openwrt"
docker exec -i $CONTAINER sh -c "cat << EOF >> /etc/config/network
config interface '$zonename'
	option ifname '$ethnetnamed'
	option proto 'dhcp'
	option metric '$constmetric'
EOF";
# add to wan firewallzone
docker exec -i $CONTAINER sh -c "uci add_list firewall.@zone[1].network="$ethnetnamed"";
docker exec -i $CONTAINER sh -c 'uci commit'
docker exec -i $CONTAINER sh -c 'sync'
# docker exec -i $CONTAINER sh -c "uci set network.@$zonename[-1].metric='$constmetric'"
docker exec -i $CONTAINER sh -c '/etc/init.d/network reload'	






# correct way but can't get it to work yet
# rule_name=$(docker exec -i $CONTAINER sh -c "uci add network "interface\u0020\'$zonename\'"");
# coniface_name=$(docker exec -i $CONTAINER sh -c "uci add network interface");
# docker exec -i $CONTAINER sh -c "uci batch << EOI
# set network.$coniface_name.ifname='$ethnetnamed'
# set network.$coniface_name.proto='dhcp'
# set network.$coniface_name.metric='$constmetric'
# EOI"


# uci add network $zonename 
# uci set network.@switch_vlan[-1].device='switch0'
# uci set network.@$zonename='interface'
# uci set network.$zonename.ifname='$ethnetnamed'
# uci set network.$zonename.proto='dhcp'
# uci set network.$zonename.metric='$constmetric'
# uci set network.@$zonename[-1].metric='$constmetric'

# docker exec -i $CONTAINER sh -c 'uci commit'



_reload_fw

fi

add_mwan3

# docker exec -i $CONTAINER sh -c '/etc/init.d/network reload'
		
				

				fi

			fi

		done
		
		sleep 5;
	done
	
	
}



main() {
	cd "${SCRIPT_DIR}"
	_create_or_start_container

	pid=$(docker inspect -f '{{.State.Pid}}' $CONTAINER)

	echo "* creating netns symlink '$CONTAINER'"
	sudo mkdir -p /var/run/netns
	sudo ln -sf /proc/$pid/ns/net /var/run/netns/$CONTAINER

	_prepare_wifi
	_prepare_network


add_multiple_wan & disown 
echo  "* Number of Multiwan '${#WAN_LIST[@]}'";
sleep "${#WAN_LIST[@]}";
monitor_parent_wan & disown
LISTJOBS=$(jobs -p)
monitor_restart_container $LISTJOBS & disown
	_reload_radio

	_reload_fw
	echo "* ready"
}

main
trap "_cleanup" EXIT
tail --pid=$pid -f /dev/null
# set +x