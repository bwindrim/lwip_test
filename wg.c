#include <stdio.h>

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "hardware/rtc.h"
#include "pico/util/datetime.h"
 
#include "wireguardif.h"
#include "private.h"

static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL; // ToDO: eliminate, as always == &wg_netif_struct
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

void wireguard_setup() {
	struct wireguardif_init_data wg;
    // IP address of wg interface (192.168.3.6/24) - "picotest"
	ip_addr_t ipaddr = IPADDR4_INIT_BYTES(192, 168, 3, 6);
	ip_addr_t netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0);
	ip_addr_t gateway = IPADDR4_INIT_BYTES(192, 168, 58, 1);

	// Setup the WireGuard device structure
	wg.private_key = PRIVATE_KEY;
	wg.listen_port = 51822;
	wg.bind_netif = NULL;

	// Register the new WireGuard network interface with lwIP
	wg_netif = netif_add(&wg_netif_struct, &ipaddr, &netmask, &gateway, &wg, &wireguardif_init, &ip_input);

	// Mark the interface as administratively up, link up flag is set automatically when peer connects
	netif_set_up(wg_netif);
 
	// Initialise the first WireGuard peer structure
	struct wireguardif_peer peer;
	wireguardif_peer_init(&peer);
	peer.public_key = PEER_PUBLIC_KEY;
	peer.preshared_key = NULL;
#if 1
	// Set up the peer's IP range (192.168.3.1/32) - "server"
    ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(192, 168, 3, 1);
    ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(255, 255, 255, 0);
#else
	// Allow all IPs through tunnel
    ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
#endif
	peer.allowed_ip = allowed_ip;
	peer.allowed_mask = allowed_mask;
	// If we know the endpoint's address we can add it here (ToDo: get from DNS, bwbirdboxes.duckdns.org)
    ip_addr_t endpoint_ip = IPADDR4_INIT_BYTES(192, 168, 58, 23); //  "Pi2B" on home network
	peer.endpoint_ip = endpoint_ip;
	peer.endport_port = 53798; // Pi2B doesn't use the default WireGuard port

	// Register the new WireGuard peer with the network interface
	wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);

	if (WIREGUARDIF_INVALID_INDEX == wireguard_peer_index) {
        printf("wireguardif_add_peer() failed\n");
        return;
    }

    if (!ip_addr_isany(&peer.endpoint_ip)) {
        // We have an IP address for the peer, so start the outbound connection
        if (wireguardif_connect(wg_netif, wireguard_peer_index)) {
            printf("wireguardif_connect() failed\n");
        } else {
            // Wait for the link to come up.
            // If we're going to initiate any TCP/IP communications then we have to
            // wait until the WireGuard link is established and marked as up. (No
            // packets will be sent to any network interface that is not marked as up,
            // anything sent before that will go to the ethernet interface and be lost.)
            // If we're only going to listen for TCP connections, or wait for UDP datagrams,
            // on the WireGuard link then we don't need to do this, as the link will have been
            // marked up (by a peer connecting) before we see any such activity.
            int seconds = 0;
            datetime_t t;
            while (!(wg_netif->flags & NETIF_FLAG_LINK_UP)) {
                char datetime_buf[256];
                char *datetime_str = &datetime_buf[0];

                printf("Waiting for WireGuard link to come up, seconds = %d\n", ++seconds);
                if (rtc_get_datetime(&t)) {
                datetime_to_str(datetime_str, sizeof(datetime_buf), &t);
                printf("Date/time = %s\n", datetime_str);
                } else{
                    printf("RTC is not running\n");
                }
                sleep_ms(1000);
            }
            printf("WireGuard link is up after %d seconds\n", seconds);
        }
    }
}

