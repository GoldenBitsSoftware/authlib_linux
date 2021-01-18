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
 *  @file  auth_lib.c
 *
 *  @brief  Authentication Library functions used to authenticate a
 *          connection between a client and server.
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>


#include "auth_config.h"
#include "auth_lib.h"
#include "auth_internal.h"
#include "auth_hal_if.h"
#include "auth_logger.h"


#define AUTH_THRD_STACK_SIZE       (4096u)
#define AUTH_THRD_PRIORITY         CONFIG_AUTH_THREAD_PRIORITY




/**
 * Forward function declarations for authentication threads.
 */
void *auth_dtls_thead(void *arg);
void *auth_chalresp_thread(void *arg);


/* ========================== local functions ========================= */

/**
 * Check auth flags consistency.
 *
 * @param flags Flags to check.
 *
 * @return  true if flags are correct, else false.
 */
static bool auth_lib_checkflags(uint32_t flags)
{
	/* Check for invalid flag combinations */

	/* server and client roles are mutually exclusive */
	if ((flags & (AUTH_CONN_SERVER | AUTH_CONN_CLIENT)) ==
	    (AUTH_CONN_SERVER | AUTH_CONN_CLIENT)) {
		return false;
	}

	/* can only define one auth method */
	if ((flags & (AUTH_CONN_DTLS_AUTH_METHOD | AUTH_CONN_CHALLENGE_AUTH_METHOD))
	    == (AUTH_CONN_DTLS_AUTH_METHOD | AUTH_CONN_CHALLENGE_AUTH_METHOD)) {
		return false;
	}

	return true;
}



/* ========================= external API ============================ */


/**
 * @see auth_lib.h
 */
int auth_lib_init(struct authenticate_conn *auth_conn, enum auth_instance_id instance,
                 auth_status_cb_t status_func, void *context, struct auth_optional_param *opt_params,
		         enum auth_flags auth_flags)
{
	int err = 0;

	/* check input params */
	if (status_func == NULL) {
        LOG_ERROR("Error, status function is NULL.");
		return AUTH_ERROR_INVALID_PARAM;
	}

	/* check auth flags */
	if (!auth_lib_checkflags(auth_flags)) {
        LOG_ERROR("Invalid auth flags.");
		return AUTH_ERROR_INVALID_PARAM;
	}

	/* init the struct to zero */
	memset(auth_conn, 0, sizeof(struct authenticate_conn));

	/* setup the status callback */
	auth_conn->status_cb = status_func;
	auth_conn->callback_context = context;

	auth_conn->cancel_auth = false;
	auth_conn->instance = instance;


	auth_conn->is_client = (auth_flags & AUTH_CONN_CLIENT) ? true : false;

#if defined(AUTH_DTLS)

	if (auth_flags & AUTH_CONN_DTLS_AUTH_METHOD) {

		{
			if (opt_params == NULL || opt_params->param_id != AUTH_DTLS_PARAM) {
				LOG_ERROR("Missing certificates for TLS/DTLS authentication.");
				return AUTH_ERROR_INVALID_PARAM;
			}

			struct auth_dtls_certs *certs = &opt_params->param_body.dtls_certs;

			// init TLS layer
			err = auth_init_dtls_method(auth_conn, certs);
		}

		if (err) {
			LOG_ERROR("Failed to initialize MBed TLS, err: %d", err);
			return err;
		}
	}
#endif

#if defined(AUTH_CHALLENGE_RESPONSE)

	if (auth_flags & AUTH_CONN_CHALLENGE_AUTH_METHOD) {

		if ((opt_params != NULL) && (opt_params->param_id == AUTH_CHALRESP_PARAM)) {

			struct auth_challenge_resp *chal_resp = &opt_params->param_body.chal_resp;

			err = auth_init_chalresp_method(auth_conn, chal_resp);

			if (err) {
				LOG_ERROR("Failed to set Challege-Response param, err: %d", err);
				return err;
			}
		}
	}
#endif


	return AUTH_SUCCESS;
}

/**
 * @see auth_lib.h
 */
int auth_lib_deinit(struct authenticate_conn *auth_conn)
{
	/* Free any resources, nothing for now, but maybe
	 * needed in the future */
	return AUTH_SUCCESS;
}

/**
 * @see auth_lib.h
 */
int auth_lib_start(struct authenticate_conn *auth_conn)
{
    /**
     * Start auth thread for this instance
     */
    ATCA_STATUS status = hal_create_thread(&auth_conn->auth_thrd, auth_chalresp_thread, auth_conn);

	return AUTH_SUCCESS;
}

/**
 * @see auth_lib.h
 */
int auth_lib_cancel(struct authenticate_conn *auth_conn)
{
	auth_conn->cancel_auth = true;

	auth_lib_set_status(auth_conn, AUTH_STATUS_CANCELED);

	return AUTH_SUCCESS;
}

/**
 * @see auth_lib.h
 */
const char *auth_lib_getstatus_str(enum auth_status status)
{
	switch (status) {
	case AUTH_STATUS_STARTED:
		return "Authentication started";
		break;

	case AUTH_STATUS_IN_PROCESS:
		return "In process";
		break;

	case AUTH_STATUS_CANCELED:
		return "Canceled";
		break;

	case AUTH_STATUS_FAILED:
		return "Failure";
		break;

	case AUTH_STATUS_AUTHENTICATION_FAILED:
		return "Authentication Failed";
		break;

	case AUTH_STATUS_SUCCESSFUL:
		return "Authentication Successful";
		break;

	default:
		break;
	}

	return "unknown";
}

/**
 * @see auth_lib.h
 */
enum auth_status auth_lib_get_status(struct authenticate_conn *auth_conn)
{
	return auth_conn->curr_status;
}

/**
 * @see auth_lib.h
 */
void auth_lib_set_status(struct authenticate_conn *auth_conn, enum auth_status status)
{
	auth_conn->curr_status = status;

	if (auth_conn->status_cb) {

		/* submit work item */
        auth_conn->status_cb(auth_conn, auth_conn->instance, auth_conn->curr_status,
                             auth_conn->callback_context);

	}
}
