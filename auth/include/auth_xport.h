/**
 * Copyright (c) 2021 Golden Bits Software, Inc.
 *
 * Use of this software is per the terms of the Apache 2.0 license
 * (here: https://www.apache.org/licenses/LICENSE-2.0) plus the following;
 *
 *
 *  THIS IS OPEN SOURCE SOFTWARE, THERE ARE NO WARRANTIES OF ANY KIND FOR ANY ASPECT OF THIS SOFTWARE.
 *  BY USING THIS SOFTWARE, YOU ACCEPT ALL LIABILITIES AND RESPONSIBILITIES FOR ANY ISSUES OR
 *  PROBLEMS ARISING OUT OF USE. YOU ARE RESPONSIBLE FOR DETERMINING THE SUITABILITY OF THIS
 *  SOFTWARE FOR YOUR USE.
 *
 *  IF YOU ARE UNSURE ABOUT USING THIS SOFTWARE, DON'T USE IT.
 *
 *  THIS SOFTWARE IS SUPPLIED BY GOLDEN BITS SOFTWARE, INC. "AS IS". NO WARRANTIES, WHETHER
 *  EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING, BUT NOT LIMITED TO, ANY IMPLIED
 *  WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT WILL GOLDEN BITS SOFTWARE BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE, EXEMPLARY,
 *  INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 *  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) COST OR EXPENSE OF ANY
 *  KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF GOLDEN BITS SOFTWARE HAS BEEN ADVISED
 *  OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. GOLDEN BITS SOFTWARE SHALL NOT BE HELD LIABLE UNDER
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file auth_xport.h
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AUTH_XPORT_H_
#define AUTH_XPORT_H_

/**
 * Transport functions and defines.
 */


/**
 * Handle to lower transport, should be treated as opaque object.
 *
 * @note A typedef is use here because the transport handle is intended to
 *       be an opaque object to the lower transport layers and to the
 *       upper layers calling into the transport.  This use satisfies
 *       the Linux coding standards.
 */
typedef void *auth_xport_hdl_t;

/**
 * The lower transport type.
 */
enum auth_xport_type {
	AUTH_XP_TYPE_NONE = 0,
    AUTH_XP_TYPE_UDP,   /* Local socket loopback */
	AUTH_XP_TYPE_BLUETOOTH,  /* not implemented */
	AUTH_XP_TYPE_SERIAL,     /* not implemented */
};


/**
 * Transport event type.
 */
enum auth_xport_evt_type {
	XP_EVT_NONE = 0,
	XP_EVT_CONNECT,
	XP_EVT_DISCONNECT,
	XP_EVT_RECONNECT,

	/* transport specific events */
	XP_EVT_SERIAL_BAUDCHANGE
};

/**
 * Transport event structure
 */
struct auth_xport_evt {
	enum auth_xport_evt_type event;

	/* transport specific event information */
	void *xport_ctx;
};

/**
 * Callback invoked when sending data asynchronously.
 *
 * @param err       Error code, 0 == success.
 * @param numbytes  Number of bytes sent, can be 0.
 */
typedef void (*send_callback_t)(int err, uint16_t numbytes);


/**
 * Function for sending data directly to the lower layer transport
 * instead of putting data on an output queue. Some lower transport
 * layers have the ability to queue outbound data, no need to double
 * buffer.
 *
 * @param  xport_hdl    Opaque transport handle.
 * @param  data         Data to send.
 * @param  len          Number of bytes to send
 *
 * @return Number of bytes sent, on error negative error value.
 */
typedef int (*send_xport_t)(auth_xport_hdl_t xport_hdl, const uint8_t *data,
			    const size_t len);


/**
 * Initializes the lower transport layer.
 *
 * @param xporthdl      New transport handle is returned here.
 * @param instance      Authentication instance.
 * @param xport_type    Transport type
 * @param xport_params  Transport specific params, passed directly to lower transport.
 *
 * @return 0 on success, else negative error number.
 */
int auth_xport_init(auth_xport_hdl_t *xporthdl,  enum auth_instance_id instance,
		    enum auth_xport_type xport_type, void *xport_params);

/**
 * De-initializes the transport.  The lower layer transport should
 * free any allocated resources.
 *
 * @param xporthdl
 *
 * @return AUTH_SUCCESS or negative error value.
 */
int auth_xport_deinit(const auth_xport_hdl_t xporthdl);

/**
 * Send event to the lower transport.
 *
 * @param xporthdl Transport handle.
 * @param event    Event
 *
 * @return  0 on success, else -1
 */

int auth_xport_event(const auth_xport_hdl_t xporthdl, struct auth_xport_evt *event);
/**
 * Sends packet of data to peer.
 *
 * @param xporthdl  Transport handle
 * @param data      Buffer to send.
 * @param len       Number of bytes to send.
 *
 * @return  Number of bytes sent on success, can be less than requested.
 *          On error, negative error code.
 */
int auth_xport_send(const auth_xport_hdl_t xporthdl, const uint8_t *data, size_t len);


/**
 * Receive data from the lower transport.
 *
 * @param xporthdl  Transport handle
 * @param buff      Buffer to read bytes into.
 * @param buf_len   Size of buffer.
 * @param timeoutMsec   Wait timeout in milliseconds.  If no bytes available, then
 *                      wait timeoutMec milliseconds.  If 0, then will not wait.
 *
 * @return Negative on error or timeout, else number of bytes received.
 */
int auth_xport_recv(const auth_xport_hdl_t xporthdl, uint8_t *buff, uint32_t buf_len, uint32_t timeoutMsec);


/**
 * Peeks at the contents of the receive queue used by the lower transport.  The
 * data returned is not removed from the receive queue.
 *
 * @param xporthdl  Transport handle
 * @param buff      Buffer to read bytes into.
 * @param buf_len   Size of buffer.
 *
 * @return Negative on error or timeout, else number of bytes peeked.
 */
int auth_xport_recv_peek(const auth_xport_hdl_t xporthdl, uint8_t *buff, uint32_t buf_len);

/**
 * Used by lower transport to put bytes reveived into rx queue.
 *
 * @param xporthdl   Transport handle.
 * @param buf        Pointer to bytes to put.
 * @param buflen     Byte len of buffer.
 *
 * @return           Number of bytes added to receive queue.
 */
int auth_xport_put_recv(const auth_xport_hdl_t xporthdl, const uint8_t *buf, size_t buflen);


/**
 * Get the number of bytes queued for sending.
 *
 * @param xporthdl  Transport handle.
 *
 * @return  Number of queued bytes, negative value on error.
 */
int auth_xport_getnum_send_queued_bytes(const auth_xport_hdl_t xporthdl);


/**
 * Get the number of bytes in the receive queue
 *
 * @param xporthdl  Transport handle.
 *
 * @return  Number of queued bytes, negative value on error.
 */
int auth_xport_getnum_recvqueue_bytes(const auth_xport_hdl_t xporthdl);

/**
 * Get the number of bytes in the receive queue, if no byte wait until
 * bytes are received or time out.
 *
 * @param xporthdl  Transport handle.l
 * @param waitmsec  Number of milliseconds to wait.
 *
 * @return  Number of queued bytes, negative value on error.
 */
int auth_xport_getnum_recvqueue_bytes_wait(const auth_xport_hdl_t xporthdl, uint32_t waitmsec);

/**
 * Sets a direct send function to the lower transport layer instead of
 * queuing bytes into an output buffer.  Some lower transports can handle
 * all of the necessary output queuing while others (serial UARTs for example)
 * may not have the ability to queue outbound byes.
 *
 * @param xporthdl   Transport handle.
 * @param send_func  Lower transport send function.
 */
void auth_xport_set_sendfunc(auth_xport_hdl_t xporthdl, send_xport_t send_func);


/**
 * Used by the lower transport to set a context for a given transport handle.  To
 * clear a previously set context, use NULL as context pointer.
 *
 * @param xporthdl   Transport handle.
 * @param context    Context pointer to set.
 *
 */
void auth_xport_set_context(auth_xport_hdl_t xporthdl, void *context);

/**
 * Returns pointer to context.
 *
 * @param xporthdl   Transport handle.
 *
 * @return  Pointer to transport layer context, else NULL
 */
void *auth_xport_get_context(auth_xport_hdl_t xporthdl);

/**
 * Get the application max payload the lower transport can handle in one
 * in one frame.  The common transport functions will break up a larger
 * application packet into multiple frames.
 *
 * @param xporthdl   Transport handle.
 *
 * @return The max payload, or negative error number.
 */
int auth_xport_get_max_payload(const auth_xport_hdl_t xporthdl);



#if defined(AUTH_UDP_XPORT)

#define IP_ADDR_ASCII_LEN           (20u)   // actual len is 15 for IP4 address format: xxx.xxx.xxx.xxx

/**
 * UDP transport param.
 */
struct auth_xp_udp_params {
    uint16_t recv_port_num;    /* UDP port number to listen on */
    uint16_t send_port_num;    /* UDP port to send messages to */
    char recv_ip_addr[IP_ADDR_ASCII_LEN];
    char send_ip_addr[IP_ADDR_ASCII_LEN];
};

/**
 * Initialize UDP lower layer transport.
 *
 * @param xport_hdl      Transport handle.
 * @param flags          RFU (Reserved for future use), set to 0.
 * @param xport_params   Udp specific transport parameters.
 *
 * @return 0 on success, else negative value.
 */
int auth_xp_udp_init(const auth_xport_hdl_t xport_hdl, uint32_t flags, void *xport_param);


/**
 * Deinit UDPtransport.
 *
 * @param xport_hdl  Transport handle
 *
 * @return 0 on success, else negative value.
 */
int auth_xp_udp_deinit(const auth_xport_hdl_t xport_hdl);


/**
 * Sends an event to lower UDP transport
 *
 * @param xporthdl   Transport handle.
 * @param event      The event.
 *
 * @return AUTH_SUCCESS, else negative error code.
 */
int auth_xp_udp_event(const auth_xport_hdl_t xporthdl, struct auth_xport_evt *event);


/**
 * Gets the maximum payload for the UDP link.
 *
 * @param xporthdl   Transport handle.
 *
 * @return Max application payload.
 */
int auth_xp_udp_get_max_payload(const auth_xport_hdl_t xporthdl);

#endif  /* AUTH_UDP_XPORT */


#endif  /* AUTH_XPORT_H_ */