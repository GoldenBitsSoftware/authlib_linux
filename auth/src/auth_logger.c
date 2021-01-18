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
 *  @file  auth_logger.c
 *
 *  @brief  Authentication library logging functions
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>


#include "auth_config.h"
#include "auth_lib.h"
#include "auth_internal.h"
#include "auth_logger.h"

#define MAX_LOG_BUF         200

static auth_log_level_t authlog_level = AUTH_LOG_DEBUG_LEVEL;
static log_output_func_t log_func = NULL;


static const char *aut_log_level_str(auth_log_level_t level)
{
    switch(level)
    {
        case AUTH_LOG_NONE_LEVEL:
            return "none";
            break;

        case AUTH_LOG_ERROR_LEVEL:
            return "error";
            break;

        case AUTH_LOG_WARNING_LEVEL:
            return "warning";
            break;


        case AUTH_LOG_DEBUG_LEVEL:
            return "debug";
            break;
    }

    return "unknown";
}


static const char *auth_basename(const char *filename)
{
    if(filename == NULL)
    {
        return NULL;
    }

    uint32_t len = strlen(filename);

    if(len == 0)
    {
        return NULL;
    }

    // work backwards looking for first '/', '\', ':', or end
    len--;
    while(len-- != 0u)
    {
        switch(filename[len])
        {
            case '/':
            case '\\':
            case ':':
                len++;  //  advance past char
                return &filename[len];
                break;

            default:
                break;
        }
    }

    return filename;
}

void auth_set_log_level(auth_log_level_t level)
{
    authlog_level = level;
}


void auth_set_logout(log_output_func_t out_func)
{
    log_func = out_func;
}

void auth_log_message(auth_log_level_t level, const char *filename,
                       uint32_t line, const char *fmt, ...)
{
    // check log level
    if(level > authlog_level || AUTH_LOG_NONE_LEVEL == level)
    {
        return;  // nothing to log
    }

    // if no output function is defined, exit
    if(log_func == NULL)
    {
        return;
    }


    char log_msg[MAX_LOG_BUF] = {0};
    char log_output[MAX_LOG_BUF] = {0};

    va_list args;
    va_start(args, fmt);
    vsnprintf(log_msg, sizeof(log_msg), fmt, args);
    va_end(args);

    // Ignore format trunction warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    snprintf(log_output, sizeof(log_output) - 1, // make sure NULL terminated
            "[%s %s line: %d] %s\r\n",
             aut_log_level_str(level), auth_basename(filename), line, log_msg);
#pragma GCC diagnostic pop

    // output log message
   log_func(log_output);
}




