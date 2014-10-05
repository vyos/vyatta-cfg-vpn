#!/bin/sh
## Script called up strongswan to bring the vti interface up/down based on the state of the IPSec tunnel.
## Called as vti_up_down vti_intf_name

source /etc/default/vyatta
source /etc/default/locale
case "$PLUTO_VERB" in
route-client)
/opt/vyatta/sbin/vyatta-vti-config.pl --updown --intf=$1 --action=up
    ;;
down-client)
/opt/vyatta/sbin/vyatta-vti-config.pl --updown --intf=$1 --action=down 
    ;;
*)
    ;;
esac
exit 0
