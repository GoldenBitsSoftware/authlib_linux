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
 *  @file  auth_chalresp.c
 *
 *  @brief  Challenge-Response method for authenticating connection.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

#include <tinycrypt/constants.h>
#include <tinycrypt/sha256.h>


#include "auth_config.h"
#include "auth_lib.h"
#include "auth_internal.h"
#include "auth_hal_if.h"
#include "auth_logger.h"


#define AUTH_SHA256_HASH                    (TC_SHA256_DIGEST_SIZE)
#define AUTH_SHARED_KEY_LEN                 (32u)
#define AUTH_CHALLENGE_LEN                  (32u)
#define AUTH_CHAL_RESPONSE_LEN              AUTH_SHA256_HASH

/* magic number to help identify and parse messages */
#define CHALLENGE_RESP_SOH                  0x65A2

/* Message IDs */
#define AUTH_CLIENT_CHAL_MSG_ID             0x01
#define AUTH_SERVER_CHALRESP_MSG_ID         0x02
#define AUTH_CLIENT_CHALRESP_MSG_ID         0x03
#define AUTH_CHALRESP_RESULT_MSG_ID         0x04

/* Timeout for receive */
#define AUTH_RX_TIMEOUT_MSEC                (3000u)


/* ensure structs are byte aligned */
#pragma pack(push, 1)

/**
 * Header for challenge response messages
 */
struct chalresp_header {
	uint16_t soh;      /* start of header */
	uint8_t msg_id;
};

/**
 * Sent by the client, contains a random challenge which the
 * server will hash with the know pre-shared key.
 */
struct client_challenge {
	struct chalresp_header hdr;
	uint8_t client_challenge[AUTH_CHALLENGE_LEN];
};

/**
 * Server response to the client challenge.  The server responds with
 * the hash of the client challenge and a server random challenge.
 */
struct server_chal_response {
	struct chalresp_header hdr;

	/* Server created hash of the client challenge and
	 * the shared key */
	uint8_t server_response[AUTH_CHAL_RESPONSE_LEN];

	/* To be hashed with the shared key by the client */
	uint8_t server_challenge[AUTH_CHALLENGE_LEN];
};

/**
 * Response from client to server challenge.
 */
struct client_chal_resp {
	struct chalresp_header hdr;
	/* hash of server challenge with shared key */
	uint8_t client_response[AUTH_CHAL_RESPONSE_LEN];
};

/* From Central or Peripheral indicating result of challenge-response */
struct auth_chalresp_result {
	struct chalresp_header hdr;
	uint8_t result; /* 0 == success, 1 == failure */
};

#pragma pack(pop)


/**
 * Shared key.
 * @brief  In a production system, the shared key should be stored in a
 * secure hardware store such as an ECC608A or TrustZone.
 */
static uint8_t default_shared_key[AUTH_SHARED_KEY_LEN] = {
	0xBD, 0x84, 0xDC, 0x6E, 0x5C, 0x77, 0x41, 0x58, 0xE8, 0xFB, 0x1D, 0xB9, 0x95, 0x39, 0x20, 0xE4,
	0xC5, 0x03, 0x69, 0x9D, 0xBC, 0x53, 0x08, 0x20, 0x1E, 0xF4, 0x72, 0x8E, 0x90, 0x56, 0x49, 0xA8
};

/* default shared key if not set */
static uint8_t *shared_key = default_shared_key;

/* If caller specifies a new shared key, it is copied into this buffer. */
static uint8_t chalresp_key[AUTH_SHARED_KEY_LEN];

/**
 * Utility function to create the hash of the random challenge and the shared key.
 * Uses Tiny Crypt hashing code.
 *
 * @param random_chal  Pointer to 32 byte value to hash with shared key.
 * @param hash         Buffer where hash is returned.
 *
 * @return AUTH_SUCCESS on success, else error value.
 */
static int auth_chalresp_hash(const uint8_t *random_chal, uint8_t *hash)
{
	int err = 0;
	struct tc_sha256_state_struct hash_state;

	tc_sha256_init(&hash_state);

	/* Update the hash with the random challenge followed by the shared key. */
	if ((err = tc_sha256_update(&hash_state, random_chal, AUTH_CHALLENGE_LEN)) != TC_CRYPTO_SUCCESS ||
	    (err = tc_sha256_update(&hash_state, shared_key, AUTH_SHARED_KEY_LEN)) != TC_CRYPTO_SUCCESS) {
		return AUTH_ERROR_CRYPTO;
	}

	/* calc the final hash */
	err = tc_sha256_final(hash, &hash_state) == TC_CRYPTO_SUCCESS ?
	      AUTH_SUCCESS : AUTH_ERROR_CRYPTO;

	return err;
}

/**
 * Checks header and id.
 *
 * @param hdr      Message header.
 * @param msg_id   Message ID to check for.
 *
 * @return true if message is valid, else false.
 */
static bool auth_check_msg(struct chalresp_header *hdr, const uint8_t msg_id)
{
	if ((hdr->soh != CHALLENGE_RESP_SOH) || (hdr->msg_id != msg_id)) {
		return false;
	}

	return true;
}


/**
 * Sends a challenge to the server.
 *
 * @param auth_conn     Authentication connection structure.
 * @param random_chal   Random 32 byte challenge to send.
 *
 * @return true if message send successfully, else false on error.
 */
static bool auth_client_send_challenge(struct authenticate_conn *auth_conn, const uint8_t *random_chal)
{
	int numbytes;
	struct client_challenge chal;

	/* build and send challenge message to Peripheral */
	memset(&chal, 0, sizeof(chal));
	chal.hdr.soh = CHALLENGE_RESP_SOH;
	chal.hdr.msg_id = AUTH_CLIENT_CHAL_MSG_ID;

	memcpy(&chal.client_challenge, random_chal, sizeof(chal.client_challenge));

	/* send to server */
	numbytes = auth_xport_send(auth_conn->xport_hdl, (uint8_t *)&chal, sizeof(chal));

	if ((numbytes <= 0) || (numbytes != sizeof(chal))) {
		/* error */
		LOG_ERROR("Error sending challenge to server, err: %d", numbytes);
		return false;
	}

	return true;
}

/**
 * Receives and processes the challenge response from the server.
 *
 * @param auth_conn     Authentication connection structure.
 * @param random_chal   32 byte challenge sent to the server.
 * @param status        Pointer to return authentication status.
 *
 * @return true on success, else false.
 */
static bool auth_client_recv_chal_resp(struct authenticate_conn *auth_conn, const uint8_t *random_chal,
				       enum auth_status *status)
{
	uint8_t hash[AUTH_CHAL_RESPONSE_LEN];
	int numbytes;
	int err;
	struct server_chal_response server_resp;
	struct client_chal_resp client_resp;
	struct auth_chalresp_result chal_result;
	uint8_t *buf = (uint8_t *)&server_resp;
	int len = sizeof(server_resp);

	while (len > 0) {

		numbytes = auth_xport_recv(auth_conn->xport_hdl, buf, len, AUTH_RX_TIMEOUT_MSEC);

		/* canceled ? */
		if (auth_conn->cancel_auth) {
			*status = AUTH_STATUS_CANCELED;
			return false;
		}

		/* timed out, try to read again */
		if (numbytes == -EAGAIN) {
			continue;
		}

		if (numbytes <= 0) {
            LOG_ERROR("Failed to read server challenge response, err: %d", numbytes);
			*status = AUTH_STATUS_FAILED;
			return false;
		}

		buf += numbytes;
		len -= numbytes;
	}

	/* check message */
	if (!auth_check_msg(&server_resp.hdr, AUTH_SERVER_CHALRESP_MSG_ID)) {
        LOG_ERROR("Invalid message received from the server.");
		*status = AUTH_STATUS_FAILED;
		return false;
	}


	/* Now verify response, is the response correct?  Hash the random challenge
	 * with the shared key. */
	err = auth_chalresp_hash(random_chal, hash);

	if (err) {
        LOG_ERROR("Failed to calc hash, err: %d", err);
		*status = AUTH_STATUS_FAILED;
		return false;
	}

	/* Does the response match what is expected? */
	if (memcmp(hash, server_resp.server_response, sizeof(hash))) {
		/* authentication failed */
        LOG_ERROR("Server authentication failed.");
		*status = AUTH_STATUS_AUTHENTICATION_FAILED;

		/* send failed message to the Peripheral */
		memset(&chal_result, 0, sizeof(chal_result));
		chal_result.hdr.soh = CHALLENGE_RESP_SOH;
		chal_result.hdr.msg_id = AUTH_CHALRESP_RESULT_MSG_ID;
		chal_result.result = 1;

		numbytes = auth_xport_send(auth_conn->xport_hdl, (uint8_t *)&chal_result, sizeof(chal_result));

		if ((numbytes <= 0) || (numbytes != sizeof(chal_result))) {
            LOG_ERROR("Failed to send authentication error result to server.");
		}

		return false;
	}

	/* init Client response message */
	memset(&client_resp, 0, sizeof(client_resp));
	client_resp.hdr.soh = CHALLENGE_RESP_SOH;
	client_resp.hdr.msg_id = AUTH_CLIENT_CHALRESP_MSG_ID;

	/* Create response to the server's random challenge */
	err = auth_chalresp_hash(server_resp.server_challenge, client_resp.client_response);

	if (err) {
        LOG_ERROR("Failed to create server response to challenge, err: %d", err);
		*status = AUTH_STATUS_FAILED;
		return false;
	}

	/* send Client's response to the Server's random challenge */
	numbytes = auth_xport_send(auth_conn->xport_hdl, (uint8_t *)&client_resp, sizeof(client_resp));

	if ((numbytes <= 0) || (numbytes != sizeof(client_resp))) {
        LOG_ERROR("Failed to send Client response.");
		*status = AUTH_STATUS_FAILED;
		return false;
	}

	/* so far so good, need to wait for Server response */
	*status = AUTH_STATUS_IN_PROCESS;
	return true;
}

/**
 * Server waits and receives a message from the client.
 *
 * @param auth_conn   Authentication connection structure.
 * @param msgbuf      Buffer to copy message into.
 * @param msglen      Buffer byte length.
 *
 * @return true if number of bytes were received, else false.
 */
static bool auth_server_recv_msg(struct authenticate_conn *auth_conn, uint8_t *msgbuf, size_t msglen)
{
	int numbytes;

	while ((int)msglen > 0) {

		numbytes = auth_xport_recv(auth_conn->xport_hdl, msgbuf, msglen, AUTH_RX_TIMEOUT_MSEC);

		if (auth_conn->cancel_auth) {
			return false;
		}

		/* timed out, retry */
		if (numbytes == -EAGAIN) {
			continue;
		}

		if (numbytes <= 0) {
			return false;
		}

		msgbuf += numbytes;
		msglen -= numbytes;
	}

	return true;
}

/**
 * Handles the client challenge, creates a hash of the challenge with the
 * shared key.
 *
 * @param auth_conn           Authentication connection structure.
 * @param server_random_chal  The server random challenge to be sent to the client.
 *
 * @return  true on success, else false on error.
 */
static bool auth_server_recv_challenge(struct authenticate_conn *auth_conn, uint8_t *server_random_chal)
{
	struct client_challenge chal;
	struct server_chal_response server_resp;
	int numbytes;

	if (!auth_server_recv_msg(auth_conn, (uint8_t *)&chal, sizeof(chal))) {
        LOG_ERROR("Failed to receive client challenge message.");
		return false;
	}

	if (!auth_check_msg(&chal.hdr, AUTH_CLIENT_CHAL_MSG_ID)) {
        LOG_ERROR("Invalid message.");
		return false;
	}

	/* create response and send back to the Client */
	server_resp.hdr.soh = CHALLENGE_RESP_SOH;
	server_resp.hdr.msg_id = AUTH_SERVER_CHALRESP_MSG_ID;

	/* copy the server's challenge for the client */
	memcpy(server_resp.server_challenge, server_random_chal,
	       sizeof(server_resp.server_challenge));

	/* Now create the response for the Client */
	auth_chalresp_hash(chal.client_challenge, server_resp.server_response);

	/* Send response */
	numbytes = auth_xport_send(auth_conn->xport_hdl, (uint8_t *)&server_resp, sizeof(server_resp));

	if ((numbytes <= 0) || (numbytes != sizeof(server_resp))) {
        LOG_ERROR("Failed to send challenge response to the Client.");
		return false;
	}

	return true;
}

/**
 *  Handles the client response to the server challenge.
 *
 * @param auth_conn            Authentication connection structure.
 * @param server_random_chal   The server random challenge sent to the client.
 * @param status               Status of the Challenge-Response authentication set here.
 *
 * @return  true on success, else false.
 */
static bool auth_server_recv_chalresp(struct authenticate_conn *auth_conn, uint8_t *server_random_chal,
				      enum auth_status *status)
{
	struct client_chal_resp client_resp;
	struct auth_chalresp_result result_resp;
	uint8_t hash[AUTH_SHA256_HASH];
	int err, numbytes;

	memset(&client_resp, 0, sizeof(client_resp));

	/* read just the header */
	if (!auth_server_recv_msg(auth_conn, (uint8_t *)&client_resp, sizeof(client_resp.hdr))) {
        LOG_ERROR("Failed to receive challenge response from the Client");
		*status = AUTH_STATUS_FAILED;
		return false;
	}

	/* This is a result message, means the Client failed to authenticate the Server. */
	if (client_resp.hdr.msg_id == AUTH_CHALRESP_RESULT_MSG_ID) {

		/* read the remainder of the message */
		auth_server_recv_msg(auth_conn, (uint8_t *)&result_resp.result, sizeof(result_resp.result));

		/* Result should be non-zero, meaning an authentication failure. */
		if (result_resp.result != 0) {
            LOG_ERROR("Unexpected result value: %d", result_resp.result);
		}

        LOG_ERROR("Client authentication failed.");
		*status = AUTH_STATUS_AUTHENTICATION_FAILED;
		return false;
	}

	/* The Client authenticated the Server (this code) response. Now verify the Client's
	 * response to the Server challenge. */
	if (!auth_server_recv_msg(auth_conn, (uint8_t *)&client_resp.hdr + sizeof(client_resp.hdr),
				  sizeof(client_resp) - sizeof(client_resp.hdr))) {
        LOG_ERROR("Failed to read Client response.");
		*status = AUTH_STATUS_FAILED;
		return false;
	}

	err = auth_chalresp_hash(server_random_chal, hash);
	if (err) {
        LOG_ERROR("Failed to create hash.");
		*status = AUTH_STATUS_FAILED;
		return false;
	}

	/* init result response message */
	memset(&result_resp, 0, sizeof(result_resp));
	result_resp.hdr.soh = CHALLENGE_RESP_SOH;
	result_resp.hdr.msg_id = AUTH_CHALRESP_RESULT_MSG_ID;

	/* verify Central's response */
	if (memcmp(hash, client_resp.client_response, sizeof(hash))) {
		/* authentication failed, the Client did not sent the correct response */
		result_resp.result = 1;
	}

	/* send result back to the Client */
	numbytes = auth_xport_send(auth_conn->xport_hdl, (uint8_t *)&result_resp, sizeof(result_resp));

	if ((numbytes <= 0) || (numbytes != sizeof(result_resp))) {
        LOG_ERROR("Failed to send Client authentication result.");
		*status = AUTH_STATUS_FAILED;
		return false;
	}

	*status = (result_resp.result == 0) ? AUTH_STATUS_SUCCESSFUL : AUTH_STATUS_AUTHENTICATION_FAILED;

	return true;
}

/**
 *  Client function used to execute Challenge-Response authentication.
 *
 * @param auth_conn  Authentication connection structure.
 *
 * @return  AUTH_SUCCESS on success, else AUTH error code.
 */
static int auth_chalresp_client(struct authenticate_conn *auth_conn)
{
	int numbytes;
	uint8_t random_chal[AUTH_CHALLENGE_LEN];
	struct auth_chalresp_result server_result;
	enum auth_status status;

	/* generate random number as challenge */
    hal_random(random_chal,  sizeof(random_chal));

	if (!auth_client_send_challenge(auth_conn, random_chal)) {
		auth_lib_set_status(auth_conn, AUTH_STATUS_FAILED);
		return AUTH_ERROR_FAILED;
	}

	/* check for cancel operation */
	if (auth_conn->cancel_auth) {
		return AUTH_ERROR_CANCELED;
	}

	/* read response from the sever */
	if (!auth_client_recv_chal_resp(auth_conn, random_chal, &status)) {
		auth_lib_set_status(auth_conn, status);
		return AUTH_ERROR_FAILED;
	}

	/* Wait for the final response from the Server indicating success or failure
	 * of the Client's response. */
	numbytes = auth_xport_recv(auth_conn->xport_hdl, (uint8_t * ) &server_result,
				   sizeof(server_result), AUTH_RX_TIMEOUT_MSEC);

	/* check for cancel operation */
	if (auth_conn->cancel_auth) {
		return AUTH_ERROR_CANCELED;
	}

	if ((numbytes <= 0) || (numbytes != sizeof(server_result))) {
		LOG_ERROR("Failed to receive server authentication result.");
		auth_lib_set_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);
		return AUTH_ERROR_FAILED;
	}

	/* check message */
	if (!auth_check_msg(&server_result.hdr, AUTH_CHALRESP_RESULT_MSG_ID)) {
        LOG_ERROR("Server rejected Client response, authentication failed.");
		auth_lib_set_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);
		return AUTH_ERROR_FAILED;
	}

	/* check the Server result */
	if (server_result.result != 0) {
        LOG_ERROR("Authentication with server failed.");
		auth_lib_set_status(auth_conn, AUTH_STATUS_AUTHENTICATION_FAILED);
		return AUTH_ERROR_FAILED;
	}

    LOG_DEBUG("Authentication with server successful.");
	auth_lib_set_status(auth_conn, AUTH_STATUS_SUCCESSFUL);

	return AUTH_SUCCESS;
}

/**
 *  Server function used to execute Challenge-Response authentication.
 *
 * @param auth_conn  Authentication connection structure.
 *
 * @return  AUTH_SUCCESS on success, else AUTH error code.
 */
static int auth_chalresp_server(struct authenticate_conn *auth_conn)
{
	enum auth_status status;
	uint8_t random_chal[AUTH_CHALLENGE_LEN];

	/* generate random number as challenge */
    hal_random(random_chal,  sizeof(random_chal));

	/* Wait for challenge from the Central */
	if (!auth_server_recv_challenge(auth_conn, random_chal)) {
		auth_lib_set_status(auth_conn, AUTH_STATUS_FAILED);
		return AUTH_ERROR_FAILED;
	}

	/* check for cancel operation */
	if (auth_conn->cancel_auth) {
		return AUTH_ERROR_CANCELED;
	}

	/* Wait for challenge response from the Client */
	auth_server_recv_chalresp(auth_conn, random_chal, &status);

	auth_lib_set_status(auth_conn, status);

	if (status != AUTH_STATUS_SUCCESSFUL) {
		LOG_ERROR("Authentication with Client failed.");
		return AUTH_ERROR_FAILED;
	}

	LOG_DEBUG("Authentication with client successful.");

	return AUTH_SUCCESS;
}


/**
 * @see auth_internal.h
 */
int auth_init_chalresp_method(struct authenticate_conn *auth_conn, struct auth_challenge_resp *chal_resp)
{
	/* verify inputs */
	if ((auth_conn == NULL) || (chal_resp == NULL)) {
		return AUTH_ERROR_INVALID_PARAM;
	}

	/* set new shared key */
	memcpy(chalresp_key, chal_resp->shared_key, AUTH_SHARED_KEY_LEN);

	/* set shared key pointer to new key */
	shared_key = chalresp_key;

	return AUTH_SUCCESS;
}


/**
 * Use hash (SHA-256) with shared key to authenticate each side.
 *
 * @param auth_conn  The authenticate_conn connection.
 */
void * auth_chalresp_thread(void *arg)
{
	int ret;
    struct authenticate_conn *auth_conn = (struct authenticate_conn *)arg;

	auth_lib_set_status(auth_conn, AUTH_STATUS_STARTED);

	/**
	 * Since a device can be a client and server at the same
	 * time need to use is_client to determine which funcs to call.
	 * refactor this code. */
	if (auth_conn->is_client) {
		ret = auth_chalresp_client(auth_conn);
	} else {
		ret = auth_chalresp_server(auth_conn);
	}

	if (ret) {
		LOG_ERROR("Challenge-Response authentication failed, err: %d", ret);
	} else {
		LOG_DEBUG("Successful Challenge-Response.");
	}

	/* End of Challenge-Response authentication thread */
	LOG_DEBUG("Challenge-Response thread complete.");
}
