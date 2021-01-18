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
 * @brief  Simple example to show how to authenticate between a
 *         client and server process over a transport.  In this sample the
 *         transport is a local socket loopback, but can be any transport
 *         such as serial, Bluetooth, or netowrk socket based.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <semaphore.h>

// auth includes
#include "auth_config.h"
#include "auth_lib.h"
#include "auth_xport.h"



#define  SERVER_PORT         12300  // random local port number
#define  CLIENT_PORT         12400
#define  LOOPBACK_ADDR      "127.0.0.1"

static bool is_server = true;

static struct authenticate_conn auth_conn;


// for getopt()
extern char *optarg;
extern int optind, opterr, optopt;

static sem_t auth_wait_sem;

/**
 * Get the command line args.
 *
 * @param argc  Number of args
 * @param argv  Pointer to command lines args.
 *
 * @return  true if args are valid, else false
 */
static bool get_cmd_line(int argc, char *argv[])
{
    int opt;
    int arg_cnt = 0;

    while((opt = getopt(argc, argv, "sc")) != -1)
    {
        switch(opt)
        {
            case 'c':
                is_server = false;
                arg_cnt++;
                break;

            case 's':
                is_server = true;
                arg_cnt++;
                break;

            default:
                return false;  // unknown option
                break;
        }
    }

    if(arg_cnt != 1)
    {
        return false;
    }

    return true;
}




/**
 *
 * @param auth_conn
 * @param instance
 * @param status
 * @param context
 * @return
 */
static void auth_status_cb(struct authenticate_conn *auth_conn, enum auth_instance_id instance,
                          enum auth_status status, void *context)
{
    // get status string
    printf("Authentication (%d) status: %s\n", instance, auth_lib_getstatus_str(instance));

    //if(status == AUTH_STATUS_SUCCESSFUL || status == )

    switch(status)
    {
        case AUTH_STATUS_SUCCESSFUL:
        case AUTH_STATUS_CANCELED:
        case AUTH_STATUS_FAILED:
        case AUTH_STATUS_AUTHENTICATION_FAILED:

            // signal semaphore for main app
            sem_post(&auth_wait_sem);
            break;

        default:
            break;

    }

}

/**
 * Initialize and start the Authentication library
 *
 * @param is_server   true if server, else client.
 * @param sock_fd     Socket used as lower transport
 *
 * @return true on success, else false
 */
static bool init_auth_lib(bool is_server, int sock_fd)
{
    uint32_t flags;
    struct auth_xp_udp_params udp_param;

    memset(&udp_param, 0, sizeof(udp_param));

    // setup the port numbers
    if(is_server)
    {
        udp_param.recv_port_num = SERVER_PORT;
        udp_param.send_port_num = CLIENT_PORT;
    }
    else
    {
        udp_param.recv_port_num = CLIENT_PORT;
        udp_param.send_port_num = SERVER_PORT;
    }


    // Using same loopback address.
    strncpy(udp_param.recv_ip_addr, LOOPBACK_ADDR, sizeof(udp_param.recv_ip_addr));
    strncpy(udp_param.send_ip_addr, LOOPBACK_ADDR, sizeof(udp_param.send_ip_addr));

    flags = is_server ? AUTH_CONN_SERVER : AUTH_CONN_CLIENT;

    flags |= AUTH_CONN_CHALLENGE_AUTH_METHOD;


    int err = auth_lib_init(&auth_conn, AUTH_INST_1_ID,
                            auth_status_cb, NULL,
                            NULL, flags);
    if(err != 0)
    {
        fprintf(stderr, "Failed to initialize authentication, err: %d\n", err);
        return false;
    }

    // init lower transport
    err = auth_xport_init(&auth_conn.xport_hdl,
                          auth_conn.instance,
                          AUTH_XP_TYPE_UDP, &udp_param);

    if(err != 0)
    {
        fprintf(stderr, "Failed to initialize loopback transport, err: %d\n", err);
        return false;
    }

    // start
    err = auth_lib_start(&auth_conn);

    if(err != 0)
    {
        fprintf(stderr, "Failed to start authentication, err: %d\n", err);
        return false;
    }

    return true;
}

/**
 * Function to route log messages to std out
 * @param log_msg
 */
static void auth_log_out(const char *log_msg)
{
    printf("%s", log_msg);
}


/**
 * Main entry point
 */
int main(int argc, char *argv[])
{
    int sock_fd = 0;
    bool start_ok = false;

    if(!get_cmd_line(argc, argv))
    {
        fprintf(stderr, "Invalid args.  use -s for server, -c for client\n");
        exit(-1);
    }

    if(sem_init(&auth_wait_sem, 0, 0) != 0)
    {
        fprintf(stderr, "Semaphore init failed, errno: %d\n", errno);
        exit(-1);
    }

    // set logging function
    auth_set_logout(auth_log_out);

    if(!init_auth_lib(is_server, sock_fd))
    {
        exit(-1);
    }

    // wait until auth completed
    sem_wait(&auth_wait_sem);

    // done
    sem_destroy(&auth_wait_sem);

    return 0;
}
