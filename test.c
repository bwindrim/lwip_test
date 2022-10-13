#include <stdio.h>

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "hardware/rtc.h"
#include "pico/util/datetime.h"
 
#include "wireguardif.h"

#include "lwip/sys.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"

extern void set_rtc_from_ntp(void);

#if 0
#define TEST_TCP_SERVER_IP "192.168.58.23"
#else
#define TEST_TCP_SERVER_IP "192.168.3.1"
#endif
#define TCP_PORT 4245
#define DEBUG_printf printf
#define BUF_SIZE 44

#define TEST_ITERATIONS 10
#define POLL_TIME_S 5

#if !defined(TEST_TCP_SERVER_IP)
#error TEST_TCP_SERVER_IP not defined
#endif

char ssid[] = "BedroomTestNetwork";
char pass[] = "dvdrtsPnk4xq";

char message[] = "HTTP/1.0 200 OK\r\nContent-type: text/html\r\n\r\n";

#if 1
static void dump_bytes(const uint8_t *bptr, uint32_t len) {
    unsigned int i = 0;

    printf("dump_bytes %d", len);
    for (i = 0; i < len;) {
        if ((i & 0x0f) == 0) {
            printf("\n");
        } else if ((i & 0x07) == 0) {
            printf(" ");
        }
        printf("%02x ", bptr[i++]);
    }
    printf("\n");
}
#define DUMP_BYTES dump_bytes
#else
#define DUMP_BYTES(A,B)
#endif

typedef struct TCP_CLIENT_T_ {
    struct tcp_pcb *tcp_pcb;
    ip_addr_t remote_addr;
    uint8_t buffer[BUF_SIZE];
    int buffer_len;
    int sent_len;
    bool complete;
    int run_count;
    bool connected;
} TCP_CLIENT_T;

static err_t tcp_client_close(void *arg) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    err_t err = ERR_OK;
    if (state->tcp_pcb != NULL) {
        tcp_arg(state->tcp_pcb, NULL);
        tcp_poll(state->tcp_pcb, NULL, 0);
        tcp_sent(state->tcp_pcb, NULL);
        tcp_recv(state->tcp_pcb, NULL);
        tcp_err(state->tcp_pcb, NULL);
        err = tcp_close(state->tcp_pcb);
        if (err != ERR_OK) {
            DEBUG_printf("close failed %d, calling abort\n", err);
            tcp_abort(state->tcp_pcb);
            err = ERR_ABRT;
        }
        state->tcp_pcb = NULL;
    }
    return err;
}

// Called with results of operation
static err_t tcp_result(void *arg, int status) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    if (status == 0) {
        DEBUG_printf("test success\n");
    } else {
        DEBUG_printf("test failed %d\n", status);
    }
    state->complete = true;
    return tcp_client_close(arg);
}

static err_t tcp_client_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    DEBUG_printf("tcp_client_sent %u\n", len);
    state->sent_len += len;

    if (state->sent_len >= BUF_SIZE) {
        // We should receive a new buffer from the server
        state->buffer_len = 0;
        state->sent_len = 0;
        DEBUG_printf("Waiting for buffer from server\n");
    }

    return ERR_OK;
}

static err_t send_to_server(void *arg, struct tcp_pcb *tpcb)
{
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    DEBUG_printf("Writing %d bytes to server\n", state->buffer_len);
    err_t err = tcp_write(tpcb, message, sizeof(message), TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
        DEBUG_printf("Failed to write data %d\n", err);
        return tcp_result(arg, -1);
    }
    DEBUG_printf("Waiting for buffer from server\n");
    return ERR_OK;
}

static err_t tcp_client_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    if (err != ERR_OK) {
        printf("connect failed %d\n", err);
        return tcp_result(arg, err);
    }
    state->connected = true;
    return send_to_server(state, tpcb);
}

static err_t tcp_client_poll(void *arg, struct tcp_pcb *tpcb) {
    DEBUG_printf("tcp_client_poll\n");
    return tcp_result(arg, -1); // no response is an error?
}

static void tcp_client_err(void *arg, err_t err) {
    if (err != ERR_ABRT) {
        DEBUG_printf("tcp_client_err %d\n", err);
        tcp_result(arg, err);
    }
}

err_t tcp_client_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    if (!p) {
		// a NULL pbuf pointer indicates EOF
        return tcp_result(arg, -1);
    }
    // this method is callback from lwIP, so cyw43_arch_lwip_begin is not required, however you
    // can use this method to cause an assertion in debug mode, if this method is called when
    // cyw43_arch_lwip_begin IS needed
    cyw43_arch_lwip_check();
    if (p->tot_len > 0) {
        DEBUG_printf("recv %d err %d\n", p->tot_len, err);
        for (struct pbuf *q = p; q != NULL; q = q->next) {
            DUMP_BYTES(q->payload, q->len);
        }
        // Receive the buffer
        const uint16_t buffer_left = BUF_SIZE - state->buffer_len;
        state->buffer_len += pbuf_copy_partial(p, state->buffer + state->buffer_len,
                                               p->tot_len > buffer_left ? buffer_left : p->tot_len, 0);
        tcp_recved(tpcb, p->tot_len);
    }
    pbuf_free(p);

    DEBUG_printf("Received %d bytes from server\n", state->buffer_len);

    // If we have received the whole buffer, check its contents
    if (state->buffer_len == sizeof(message)) {
        if (memcmp(state->buffer, message, sizeof(message))) {
            DEBUG_printf("Response does not match message\n");
            return -1;
        }
    }

        state->run_count++;
        if (state->run_count >= TEST_ITERATIONS) {
            tcp_result(arg, 0);
            return ERR_OK;
        }

    return send_to_server(state, tpcb);
}

static bool tcp_client_open(void *arg) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    DEBUG_printf("Connecting to %s port %u\n", ip4addr_ntoa(&state->remote_addr), TCP_PORT);
    state->tcp_pcb = tcp_new_ip_type(IP_GET_TYPE(&state->remote_addr));
    if (!state->tcp_pcb) {
        DEBUG_printf("failed to create pcb\n");
        return false;
    }

    tcp_arg(state->tcp_pcb, state);
    tcp_poll(state->tcp_pcb, tcp_client_poll, POLL_TIME_S * 2);
    tcp_sent(state->tcp_pcb, tcp_client_sent);
    tcp_recv(state->tcp_pcb, tcp_client_recv);
    tcp_err(state->tcp_pcb, tcp_client_err);

    state->buffer_len = 0;

    // cyw43_arch_lwip_begin/end should be used around calls into lwIP to ensure correct locking.
    // You can omit them if you are in a callback from lwIP. Note that when using pico_cyw_arch_poll
    // these calls are a no-op and can be omitted, but it is a good practice to use them in
    // case you switch the cyw43_arch type later.
    cyw43_arch_lwip_begin();
    err_t err = tcp_connect(state->tcp_pcb, &state->remote_addr, TCP_PORT, tcp_client_connected);
    cyw43_arch_lwip_end();

    return err == ERR_OK;
}

// Perform initialisation
static TCP_CLIENT_T* tcp_client_init(void) {
    TCP_CLIENT_T *state = calloc(1, sizeof(TCP_CLIENT_T));
    if (!state) {
        DEBUG_printf("failed to allocate state\n");
        return NULL;
    }
    ip4addr_aton(TEST_TCP_SERVER_IP, &state->remote_addr);
    return state;
}

void run_tcp_client_test(void) {
    TCP_CLIENT_T *state = tcp_client_init();
    if (!state) {
        return;
    }
    if (!tcp_client_open(state)) {
        tcp_result(state, -1);
        return;
    }
    while(!state->complete) {
        // the following #ifdef is only here so this same example can be used in multiple modes;
        // you do not need it in your code
#if PICO_CYW43_ARCH_POLL
        // if you are using pico_cyw43_arch_poll, then you must poll periodically from your
        // main loop (not from a timer) to check for WiFi driver or lwIP work that needs to be done.
        cyw43_arch_poll();
        sleep_ms(1);
#else
        // if you are not using pico_cyw43_arch_poll, then WiFI driver and lwIP work
        // is done via interrupt in the background. This sleep is just an example of some (blocking)
        // work you might be doing.
        sleep_ms(1000);
#endif
    }
    free(state);
}

static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL; // ToDO: eliminate, as always == &wg_netif_struct
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
#if 0
static bool link_is_up = false;
static void link_callback(struct netif *pNetif){
    printf("*** netif up = %d\n", pNetif->flags);

    if (pNetif->flags & NETIF_FLAG_LINK_UP) {
        link_is_up = true;
    }
}
#endif
static void wireguard_setup() {
	struct wireguardif_init_data wg;
    // IP address of wg interface (192.168.3.6/24) - "picotest"
	ip_addr_t ipaddr = IPADDR4_INIT_BYTES(192, 168, 3, 6);
	ip_addr_t netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0);
	ip_addr_t gateway = IPADDR4_INIT_BYTES(192, 168, 58, 1);

	// Setup the WireGuard device structure
	wg.private_key = "CM3/AgWrSFy1fbyZ55iiciTBZXOjgjhsuL8w6WXN41E=";
	wg.listen_port = 51822;
	wg.bind_netif = NULL;

	// Register the new WireGuard network interface with lwIP
	wg_netif = netif_add(&wg_netif_struct, &ipaddr, &netmask, &gateway, &wg, &wireguardif_init, &ip_input);

//    netif_set_link_callback(wg_netif, link_callback);

	// Mark the interface as administratively up, link up flag is set automatically when peer connects
	netif_set_up(wg_netif);
 
	// Initialise the first WireGuard peer structure
	struct wireguardif_peer peer;
	wireguardif_peer_init(&peer);
	peer.public_key = "UL1lDnyVLeF9anKRgt4clUBCJBR30NAUOS+RN+37qlI=";
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

    // Start the RTC
    // Start on Friday 5th of June 2020 15:45:00
    datetime_t t;
#if 0
    if (!rtc_running()) {
        // Set up the RTC
        // Start on Friday 5th of June 2020 15:45:00
        datetime_t t = {
            .year  = 2020,
            .month = 06,
            .day   = 05,
            .dotw  = 5, // 0 is Sunday, so 5 is Friday
            .hour  = 15,
            .min   = 45,
            .sec   = 00
        };
        rtc_init();
        rtc_set_datetime(&t);
    }
#else
    if (!rtc_running()) {
        set_rtc_from_ntp();
    }
#endif
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

int main() {
    int connect_failed = 1;
	stdio_init_all();

    for (int tries = 0; tries < 1; ++tries) {
        if (cyw43_arch_init_with_country(CYW43_COUNTRY_UK)) {
            printf("failed to initialise\n");
            return 1;
        }
        printf("initialised\n");

        cyw43_arch_enable_sta_mode();
        
        connect_failed = cyw43_arch_wifi_connect_timeout_ms(ssid, pass, CYW43_AUTH_WPA2_AES_PSK, 10000);

        if (connect_failed) {
            printf("failed to connect\n");
            cyw43_arch_deinit();
        } else {
            printf("Connected.\n");
            break;
        }
    }

    if (connect_failed)
        return connect_failed;

    wireguard_setup();
    sleep_ms(2000);

    run_tcp_client_test();
    cyw43_arch_deinit();
	return 0;
}
