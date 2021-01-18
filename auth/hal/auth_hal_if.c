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
 *
 *
 *  @file  auth_hal_if.c
 *
 *  @brief  Platform hal interface
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <semaphore.h>
#include <stdbool.h>


#include "auth_hal_if.h"

typedef struct
{
    sem_t *semaphore;
    unsigned max_sem_value;
} sem_instance_t;


static pthread_mutex_t sem_count_mutex = PTHREAD_MUTEX_INITIALIZER;


/**
 * \brief Application callback for creating a mutex object
 * \param[in,out] ppMutex location to receive ptr to mutex
 * \param[in,out] pName String used to identify the mutex
 */
ATCA_STATUS hal_create_mutex(void ** ppMutex, char* pName)
{
    sem_t * sem;
    static int mutex_cnt;
    char temp_name[40];

    if (!ppMutex)
    {
        return ATCA_BAD_PARAM;
    }

   if (!pName)
   {
        //pName = "atca_mutex";
        sprintf(temp_name, "mutex_%d", mutex_cnt++);
        pName = temp_name;
    }

    sem = sem_open(pName, (O_CREAT | O_RDWR), (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP), 1);
    if (SEM_FAILED == sem)
    {
        return ATCA_GEN_FAIL;
    }

    *ppMutex = sem;

    return ATCA_SUCCESS;
}

/*
 * \brief Application callback for destroying a mutex object
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_destroy_mutex(void * pMutex)
{
    sem_t * sem = (sem_t*)pMutex;

    if (!sem)
    {
        return ATCA_BAD_PARAM;
    }

    if (-1 == sem_close(sem))
    {
        return ATCA_GEN_FAIL;
    }
    else
    {
        return ATCA_SUCCESS;
    }
}


/*
 * \brief Application callback for locking a mutex
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_lock_mutex(void * pMutex)
{
    sem_t * sem = (sem_t*)pMutex;

    if (!sem)
    {
        return ATCA_BAD_PARAM;
    }

    if (-1 == sem_wait(sem))
    {
        return ATCA_GEN_FAIL;
    }
    else
    {
        return ATCA_SUCCESS;
    }
}

/*
 * \brief Application callback for unlocking a mutex
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_unlock_mutex(void * pMutex)
{
    sem_t * sem = (sem_t*)pMutex;

    if (!sem)
    {
        return ATCA_BAD_PARAM;
    }

    if (-1 == sem_post(sem))
    {
        return ATCA_GEN_FAIL;
    }
    else
    {
        return ATCA_SUCCESS;
    }
}

ATCA_STATUS hal_create_sem(void **sem, unsigned init_value, unsigned max_value)
{
    sem_t * semaphore;
    static int sem_cnt;
    char temp_name[40];

    if (!sem)
    {
        return ATCA_BAD_PARAM;
    }

    sem_instance_t *sem_inst = malloc(sizeof(sem_instance_t));

    if(sem_inst == NULL)
    {
        return ATCA_FUNC_FAIL;
    }

    sprintf(temp_name, "sem_%d", sem_cnt++);

    sem_inst->semaphore = sem_open(temp_name,
                                   (O_CREAT | O_RDWR), (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP), init_value);
    if (SEM_FAILED == semaphore)
    {
        free(sem_inst);
        return ATCA_GEN_FAIL;
    }

    sem_inst->max_sem_value = max_value;

    *sem = sem_inst;

    return ATCA_SUCCESS;
}

ATCA_STATUS hel_destroy_sem(void *sem)
{
    sem_instance_t *sem_inst = (sem_instance_t*)sem;

    if (!sem_inst)
    {
        return ATCA_BAD_PARAM;
    }

    if (-1 == sem_close(sem_inst->semaphore))
    {
        return ATCA_GEN_FAIL;
    }
    else
    {
        free(sem_inst);
        return ATCA_SUCCESS;
    }
}


ATCA_STATUS hal_wait_sem(void *sem)
{
    sem_instance_t *sem_inst = (sem_instance_t*)sem;

    if (!sem_inst)
    {
        return ATCA_BAD_PARAM;
    }

    int ret = sem_wait(sem_inst->semaphore);

    return ret == 0 ? ATCA_SUCCESS : ATCA_GEN_FAIL;
}

ATCA_STATUS hal_wait_sem_timeout(void *sem, unsigned timeout_msec)
{
    struct timespec time_val;
    sem_instance_t *sem_inst = (sem_instance_t*)sem;

    if (!sem_inst)
    {
        return ATCA_BAD_PARAM;
    }

    clock_gettime(CLOCK_REALTIME, &time_val);

    // convert milliseconds to seconds and nano seconds
    time_val.tv_sec += (timeout_msec / 1000u);
    time_val.tv_nsec += (timeout_msec % 1000) * 1000000u;

    int ret = sem_timedwait(sem_inst->semaphore, &time_val);

    if(ret != 0 && errno == ETIMEDOUT)
    {
        return ATCA_TIMEOUT;
    }

    return ret == 0 ? ATCA_SUCCESS : ATCA_GEN_FAIL;
}

ATCA_STATUS hal_give_sem(void *sem)
{
    int sem_val = 0;
    int ret = 0;
    sem_instance_t *sem_inst = (sem_instance_t*)sem;

    if (!sem_inst)
    {
        return ATCA_BAD_PARAM;
    }

    // check the max value, this is a two step operation so
    // lock access while performing
    if(pthread_mutex_lock(&sem_count_mutex) != 0)
    {
        return ATCA_GEN_FAIL;
    }

    ret = sem_getvalue(sem_inst->semaphore, &sem_val);

    if((ret == 0) && (sem_val < (int)sem_inst->max_sem_value))
    {
        ret = sem_post(sem_inst->semaphore);
    }

    // unlock
    pthread_mutex_unlock(&sem_count_mutex);

    return ret == 0 ? ATCA_SUCCESS : ATCA_GEN_FAIL;
}


ATCA_STATUS hal_create_thread(void ** ppThread, thread_func_t thread_entry, void *arg)
{
    pthread_t **thread_id = (pthread_t **)ppThread;

    if(ppThread == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    *thread_id = malloc(sizeof(pthread_t));

    /**
     * If necessary add'l thread attributes can be set here
     */
    pthread_attr_t thrd_attr;
    pthread_attr_init(&thrd_attr);

    if(pthread_create(*thread_id, &thrd_attr, thread_entry, arg) != 0)
    {
        return ATCA_FUNC_FAIL;
    }


    return ATCA_SUCCESS;
}


ATCA_STATUS hal_random(unsigned char *buf, unsigned len)
{
    // use pseudo random generator
    for(unsigned cnt = 0; cnt < len; cnt++, buf++)
    {
        // NOTE: Can be smarter about this, rand() returns 4 bytes
        //       here we're only using one byte.
        *buf = (uint8_t)rand();
    }

    return ATCA_SUCCESS;
}
