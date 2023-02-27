/*
 SHM refclock test client based on chronyd/chronyc SHM refclock driver.

 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2009
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 **********************************************************************
 */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/errno.h>
#include <sys/shm.h>

#define SHMKEY 0x4e545030

struct shmTime {
	int    mode; /* 0 - if valid set
								*       use values,
								*       clear valid
								* 1 - if valid set
								*       if count before and after read of values is equal,
								*         use values
								*       clear valid
								*/
	volatile int count;
	time_t clockTimeStampSec;
	int    clockTimeStampUSec;
	time_t receiveTimeStampSec;
	int    receiveTimeStampUSec;
	int    leap;
	int    precision;
	int    nsamples;
	volatile int valid;
	int    clockTimeStampNSec;
	int    receiveTimeStampNSec;
	int    dummy[8];
};

static void *data;

static int shm_initialise() {
	int id, param, perm;
	struct shmTime *shm;

	param = 0;
	perm = 0600;

	id = shmget(SHMKEY + param, sizeof (struct shmTime), IPC_CREAT | perm);
	if (id == -1) {
		printf("shmget() failed : %s\n", strerror(errno));
		return 0;
	}

	shm = (struct shmTime *)shmat(id, 0, 0);
	if ((long)shm == -1) {
		printf("shmat() failed : %s\n", strerror(errno));
		return 0;
	}

	data = shm;
	return 1;
}

static int shm_poll()
{
	struct timespec receive_ts, clock_ts;
	struct shmTime t, *shm;

	shm = (struct shmTime *)data;
	if (shm == NULL) {
		printf("SHM sample not availbale\n");
		return 0;
	}

	t = *shm;

	if ((t.mode == 1 && t.count != shm->count) ||
		!(t.mode == 0 || t.mode == 1) || !t.valid)
	{
		printf("SHM sample ignored mode=%d count=%d valid=%d\n",
			t.mode, t.count, t.valid);
		return 0;
	}

	shm->valid = 0;

	receive_ts.tv_sec = t.receiveTimeStampSec;
	clock_ts.tv_sec = t.clockTimeStampSec;

	if (t.clockTimeStampNSec / 1000 == t.clockTimeStampUSec &&
			t.receiveTimeStampNSec / 1000 == t.receiveTimeStampUSec)
	{
		receive_ts.tv_nsec = t.receiveTimeStampNSec;
		clock_ts.tv_nsec = t.clockTimeStampNSec;
	} else {
		receive_ts.tv_nsec = 1000 * t.receiveTimeStampUSec;
		clock_ts.tv_nsec = 1000 * t.clockTimeStampUSec;
	}

	printf("SHM sample received receive_ts.tv_sec=%ld, receive_ts.tv_nsec=%ld,"
		" clock_ts.tv_sec=%ld, clock_ts.tv_nsec=%ld, leap=%d\n", receive_ts.tv_sec,
		receive_ts.tv_nsec, clock_ts.tv_sec, clock_ts.tv_nsec, t.leap);

	return 1;
}

int main() {
	printf("sizeof(int) = %zu\n", sizeof(int));
	printf("sizeof(unsigned) = %zu\n", sizeof(unsigned));
	printf("sizeof(time_t) = %zu\n", sizeof(time_t));
	printf("sizeof(struct shmTime) = %zu\n", sizeof(struct shmTime));
	printf("\n");
	printf("offsetof(struct shmTime, mode) = %zu\n", offsetof(struct shmTime, mode));
	printf("offsetof(struct shmTime, count) = %zu\n", offsetof(struct shmTime, count));
	printf("offsetof(struct shmTime, clockTimeStampSec) = %zu\n", offsetof(struct shmTime, clockTimeStampSec));
	printf("offsetof(struct shmTime, clockTimeStampUSec) = %zu\n", offsetof(struct shmTime, clockTimeStampUSec));
	printf("offsetof(struct shmTime, receiveTimeStampSec) = %zu\n", offsetof(struct shmTime, receiveTimeStampSec));
	printf("offsetof(struct shmTime, receiveTimeStampUSec) = %zu\n", offsetof(struct shmTime, receiveTimeStampUSec));
	printf("offsetof(struct shmTime, leap) = %zu\n", offsetof(struct shmTime, leap));
	printf("offsetof(struct shmTime, precision) = %zu\n", offsetof(struct shmTime, precision));
	printf("offsetof(struct shmTime, nsamples) = %zu\n", offsetof(struct shmTime, nsamples));
	printf("offsetof(struct shmTime, valid) = %zu\n", offsetof(struct shmTime, valid));
	printf("offsetof(struct shmTime, clockTimeStampNSec) = %zu\n", offsetof(struct shmTime, clockTimeStampNSec));
	printf("offsetof(struct shmTime, receiveTimeStampNSec) = %zu\n", offsetof(struct shmTime, receiveTimeStampNSec));
	printf("offsetof(struct shmTime, dummy) = %zu\n", offsetof(struct shmTime, dummy));

	int r;

	r = shm_initialise();
	assert(r == 1);

	for (;;) {
		(void)shm_poll();
		(void)sleep(5);
	}
}
