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
 * SPDX-License-Identifier: Apache-2.0
 *
 *  @file  auth_hal_if.h
 *
 *  @brief  Platform HAL interface
 *
 */

#ifndef AUTH_HAL_IF_H
#define AUTH_HAL_IF_H




/* all status codes for the ATCA lib are defined here */

typedef enum
{
    ATCA_SUCCESS                = 0x00, //!< Function succeeded.
    ATCA_CONFIG_ZONE_LOCKED     = 0x01,
    ATCA_DATA_ZONE_LOCKED       = 0x02,
    ATCA_INVALID_POINTER,
    ATCA_INVALID_LENGTH,
    ATCA_WAKE_FAILED            = 0xD0, //!< response status byte indicates CheckMac failure (status byte = 0x01)
    ATCA_CHECKMAC_VERIFY_FAILED = 0xD1, //!< response status byte indicates CheckMac failure (status byte = 0x01)
    ATCA_PARSE_ERROR            = 0xD2, //!< response status byte indicates parsing error (status byte = 0x03)
    ATCA_STATUS_CRC             = 0xD4, //!< response status byte indicates DEVICE did not receive data properly (status byte = 0xFF)
    ATCA_STATUS_UNKNOWN         = 0xD5, //!< response status byte is unknown
    ATCA_STATUS_ECC             = 0xD6, //!< response status byte is ECC fault (status byte = 0x05)
    ATCA_STATUS_SELFTEST_ERROR  = 0xD7, //!< response status byte is Self Test Error, chip in failure mode (status byte = 0x07)
    ATCA_FUNC_FAIL              = 0xE0, //!< Function could not execute due to incorrect condition / state.
    ATCA_GEN_FAIL               = 0xE1, //!< unspecified error
    ATCA_BAD_PARAM              = 0xE2, //!< bad argument (out of range, null pointer, etc.)
    ATCA_INVALID_ID             = 0xE3, //!< invalid device id, id not set
    ATCA_INVALID_SIZE           = 0xE4, //!< Count value is out of range or greater than buffer size.
    ATCA_RX_CRC_ERROR           = 0xE5, //!< CRC error in data received from device
    ATCA_RX_FAIL                = 0xE6, //!< Timed out while waiting for response. Number of bytes received is > 0.
    ATCA_RX_NO_RESPONSE         = 0xE7, //!< Not an error while the Command layer is polling for a command response.
    ATCA_RESYNC_WITH_WAKEUP     = 0xE8, //!< Re-synchronization succeeded, but only after generating a Wake-up
    ATCA_PARITY_ERROR           = 0xE9, //!< for protocols needing parity
    ATCA_TX_TIMEOUT             = 0xEA, //!< for Microchip PHY protocol, timeout on transmission waiting for master
    ATCA_RX_TIMEOUT             = 0xEB, //!< for Microchip PHY protocol, timeout on receipt waiting for master
    ATCA_TOO_MANY_COMM_RETRIES  = 0xEC, //!< Device did not respond too many times during a transmission. Could indicate no device present.
    ATCA_SMALL_BUFFER           = 0xED, //!< Supplied buffer is too small for data required
    ATCA_COMM_FAIL              = 0xF0, //!< Communication with device failed. Same as in hardware dependent modules.
    ATCA_TIMEOUT                = 0xF1, //!< Timed out while waiting for response. Number of bytes received is 0.
    ATCA_BAD_OPCODE             = 0xF2, //!< opcode is not supported by the device
    ATCA_WAKE_SUCCESS           = 0xF3, //!< received proper wake token
    ATCA_EXECUTION_ERROR        = 0xF4, //!< chip was in a state where it could not execute the command, response status byte indicates command execution error (status byte = 0x0F)
    ATCA_UNIMPLEMENTED          = 0xF5, //!< Function or some element of it hasn't been implemented yet
    ATCA_ASSERT_FAILURE         = 0xF6, //!< Code failed run-time consistency check
    ATCA_TX_FAIL                = 0xF7, //!< Failed to write
    ATCA_NOT_LOCKED             = 0xF8, //!< required zone was not locked
    ATCA_NO_DEVICES             = 0xF9, //!< For protocols that support device discovery (kit protocol), no devices were found
    ATCA_HEALTH_TEST_ERROR      = 0xFA, //!< random number generator health test error
    ATCA_ALLOC_FAILURE          = 0xFB, //!< Couldn't allocate required memory
    ATCA_USE_FLAGS_CONSUMED     = 0xFC, //!< Use flags on the device indicates its consumed fully
    ATCA_NOT_INITIALIZED        = 0xFD, //!< The library has not been initialized so the command could not be executed
} ATCA_STATUS;


/**
 * @brief Platform types
 */

typedef void * hal_mutex;
typedef void * hal_sem;
typedef void * hal_thread;


ATCA_STATUS hal_create_mutex(void ** ppMutex, char* pName);
ATCA_STATUS hal_destroy_mutex(void * pMutex);
ATCA_STATUS hal_lock_mutex(void * pMutex);
ATCA_STATUS hal_unlock_mutex(void * pMutex);


/**
 * Thread entry point
 */
typedef void *(*thread_func_t)(void *);

ATCA_STATUS hal_create_thread(void ** ppThread, thread_func_t thread_entry, void *arg);

/**
 * Creates a semaphore
 *
 * @param sem
 * @param init_value  Initial value of semaphore
 *
 * @return
 */
ATCA_STATUS hal_create_sem(void **sem, unsigned init_value, unsigned max_value);

ATCA_STATUS hel_destroy_sem(void *sem);

ATCA_STATUS hal_wait_sem(void *sem);

ATCA_STATUS hal_wait_sem_timeout(void *sem, unsigned timeout_msec);

ATCA_STATUS hal_give_sem(void *sem);

ATCA_STATUS hal_random(unsigned char *buf, unsigned len);

#endif

