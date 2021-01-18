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
 *  @file  auth_xport_loopback.c
 *
 *  @brief  Loopback transport, will loopback over a local socket.
 *          Primarily used for development and testing.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include <sys/socket.h>

#include "auth_config.h"
#include "auth_logger.h"
#include "auth_lib.h"
#include "auth_xport.h"
#include "auth_internal.h"



#define UDP_LINK_MTU                (1024u)


/* UDP transport instance */
struct udp_xp_instance {
	bool in_use;
	auth_xport_hdl_t xport_hdl;

	/* Socket and address used to send */
	int send_socket_fd;
    struct sockaddr_in send_addr;

    /**
     * UDP network info
     */
	uint16_t send_port_num;
	uint16_t recv_port_num;
	char recv_ip_addr[IP_ADDR_ASCII_LEN];
	char send_ip_addr[IP_ADDR_ASCII_LEN];

	volatile bool shutdown_rx_thread;
    hal_thread recv_thrd;
};


static struct udp_xp_instance udp_xp_inst[NUM_AUTH_INSTANCES];



/**
 * Gets a Loopback transport instance.
 *
 * @return Pointer to loopback transport, else NULL on error.
 */
static struct udp_xp_instance *auth_xp_udp_get_instance(void)
{
	uint32_t cnt;

	for (cnt = 0; cnt < NUM_AUTH_INSTANCES; cnt++) {

		if (!udp_xp_inst[cnt].in_use) {
            udp_xp_inst[cnt].in_use = true;
			return &udp_xp_inst[cnt];
		}
	}

	return NULL;
}

/**
 * Free Loopback transport instance.
 *
 * @param loopback_inst  Pointer to serial transport instance.
 */
static void auth_xp_udp_free_instance(struct udp_xp_instance *udp_inst)
{
	if (udp_inst != NULL) {

        udp_inst->in_use = false;
        udp_inst->xport_hdl = NULL;
        udp_inst->recv_port_num = 0;
        udp_inst->send_port_num = 0;
	}
}


/**
 * Receive thread, reads data off socket and forwards to upper
 * common transport layers.
 *
 * @param arg
 */
static void *auth_xp_udp_recv(void *arg)
{
    int fd;
    size_t num_bytes;
    struct sockaddr_in recv_addr;
    uint8_t *rx_buf;
    auth_xport_hdl_t xport_hdl = (auth_xport_hdl_t)arg;
    struct udp_xp_instance *xp_inst;
    uint32_t recv_ip_addr;
    uint16_t begin_offset, byte_cnt;

    // get instance
    xp_inst = (struct udp_xp_instance *)auth_xport_get_context(xport_hdl);

    if(xp_inst == NULL)
    {
        LOG_ERROR("Failed to get transport instance.");
        return 0;
    }


    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if(fd == -1)
    {
        free(rx_buf);
        LOG_ERROR("Failed to create socket, errno: %d", errno);
        return 0;
    }


    recv_ip_addr = inet_addr(xp_inst->recv_ip_addr);

    memset((char *) &recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = recv_ip_addr; /* host-to-network endian */
    recv_addr.sin_port = htons(xp_inst->recv_port_num);

    // bind address to address
    if(bind(fd, (const struct sockaddr*)&recv_addr, sizeof(recv_addr)) < 0)
    {
        LOG_ERROR("Failed to bind to IP address: %s, errno: %d", xp_inst->recv_ip_addr, errno);
        return 0;
    }

    rx_buf = malloc(UDP_LINK_MTU);

    if(rx_buf == NULL)
    {
        close(fd);
        LOG_ERROR("Failed to allocate rx buffer, errno: %d", errno);
        return 0;
    }

    while(!xp_inst->shutdown_rx_thread)
    {
        ssize_t byte_recv = recvfrom(fd, rx_buf, UDP_LINK_MTU, 0, NULL, 0);

        if((int)byte_recv == -1)
        {
            LOG_ERROR("Failed to receive from source, errno: %d", errno);
            continue;
        }

        LOG_DEBUG("Received %d bytes.", (int)byte_recv);

        if(!xp_inst->shutdown_rx_thread) {

            // NOTE: With UDP we should receive a full message without any fragmentation
            if(auth_message_get_fragment(rx_buf, (uint16_t)byte_recv, &begin_offset, &byte_cnt)) {

                // forward common transport layer
                auth_message_assemble(xport_hdl, rx_buf, byte_recv);
            }
            else
            {
                LOG_ERROR("Didn't recv full packet.");
            }
        }
    }

    free(rx_buf);

    return 0;
}


/**
 * Send bytes over UDP
 * @param xport_hdl  Transport handle.
 * @param data       Bytes to send.
 * @param len        Number of bytes to send.
 *
 * @return  Number of bytes sent on success, else negative error value.
 */
static int auth_xp_udp_send(auth_xport_hdl_t xport_hdl, const uint8_t *data,
			                     const size_t len)
{
	if (len > UDP_LINK_MTU) {
		LOG_ERROR("Too many bytes to send.");
		return AUTH_ERROR_INVALID_PARAM;
	}

	struct udp_xp_instance *udp_inst = (struct udp_xp_instance *)auth_xport_get_context(xport_hdl);
    socklen_t socklen = sizeof(udp_inst->send_addr);

	/* Send out socket */
    ssize_t bytes_sent = sendto(udp_inst->send_socket_fd, data, len, 0,
                                (const struct sockaddr *)&udp_inst->send_addr, socklen);

    if((int)bytes_sent == -1)
    {
        LOG_ERROR("Failed to send data, errno: %d", errno);
    }
    else
    {
        LOG_DEBUG("Sent %d bytes.", (uint32_t)bytes_sent);
    }


	return (int)bytes_sent;
}


/**
 * @see auth_xport.h
 */
int auth_xp_udp_init(const auth_xport_hdl_t xport_hdl, uint32_t flags,
			              void *xport_param)
{
	struct auth_xp_udp_params *udp_param =
		              (struct auth_xp_udp_params*)xport_param;

	struct udp_xp_instance *udp_inst = auth_xp_udp_get_instance();

	if (udp_inst == NULL) {
		LOG_ERROR("No free UDP xport instances.");
		return AUTH_ERROR_NO_RESOURCE;
	}

    udp_inst->shutdown_rx_thread = false;


    /* Save off vars */
    udp_inst->xport_hdl = xport_hdl;
    udp_inst->send_port_num = udp_param->send_port_num;
    udp_inst->recv_port_num = udp_param->recv_port_num;
    strncpy(udp_inst->send_ip_addr, udp_param->send_ip_addr, sizeof(udp_inst->send_ip_addr));
    strncpy(udp_inst->recv_ip_addr, udp_param->recv_ip_addr, sizeof(udp_inst->recv_ip_addr));

    /* Create send address and socket, the receive socket and
     * address is created in the receive thread. */
    udp_inst->send_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    // IP address to send messages to
    in_addr_t send_addr = inet_addr(udp_inst->send_ip_addr);

    memset(&udp_inst->send_addr, 0, sizeof(udp_inst->send_addr));
    udp_inst->send_addr.sin_family = AF_INET;
    udp_inst->send_addr.sin_addr.s_addr = send_addr;
    udp_inst->send_addr.sin_port = htons(udp_inst->send_port_num);


	/* set UDP instance into xport handle */
	auth_xport_set_context(xport_hdl, udp_inst);

	auth_xport_set_sendfunc(xport_hdl, auth_xp_udp_send);

	/* Start receive thread, will block on read of socket */
    hal_create_thread(&udp_inst->recv_thrd, auth_xp_udp_recv, xport_hdl);

	return AUTH_SUCCESS;
}

/**
 * @see auth_xport.h
 */
int auuth_xp_udp_deinit(const auth_xport_hdl_t xport_hdl)
{
	struct udp_xp_instance *udp_inst = (struct udp_xp_instance *)auth_xport_get_context(xport_hdl);

    udp_inst->shutdown_rx_thread = true;

	// close socket
	if(udp_inst->send_socket_fd != 0)
    {
        close(udp_inst->send_socket_fd);
        udp_inst->send_socket_fd = 0;
    }

	auth_xp_udp_free_instance(udp_inst);

	auth_xport_set_context(xport_hdl, NULL);

	return AUTH_SUCCESS;
}


/**
 * @see auth_xport.h
 */
int auth_xp_udp_event(const auth_xport_hdl_t xporthdl, struct auth_xport_evt *event)
{
	/* No-op */
	return AUTH_SUCCESS;
}

/**
 * @see auth_xport.h
 */
int auth_xp_udp_get_max_payload(const auth_xport_hdl_t xporthdl)
{
	return UDP_LINK_MTU;
}





