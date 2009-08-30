/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <zmq.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>

int main (int argc, char *argv [])
{
    const char *bind_to;
    int message_count;
    int message_size;
    void *ctx;
    void *s;
    int rc;
    int i;
    zmq_msg_t msg;
    long long elapsed;
    long long throughput;

    if (argc != 4) {
        printf ("usage: local_thr <bind-to> <message-count> "
            "<message-size>\n");
        return 1;
    }
    bind_to = argv [1];
    message_count = atoi (argv [2]);
    message_size = atoi (argv [3]);

    ctx = zmq_init (1, 1);
    assert (ctx);

    s = zmq_socket (ctx, ZMQ_P2P);
    assert (s);

    rc = zmq_bind (s, bind_to);
    assert (rc == 0);

    rc = zmq_msg_init (&msg);
    assert (rc == 0);

    rc = zmq_recv (s, &msg, 0);
    assert (rc == 0);
    assert (zmq_msg_size (&msg) == message_size);

    timeval start;
    rc = gettimeofday (&start, NULL);
    assert (rc == 0);

    for (i = 0; i != message_count - 1; i++) {
        rc = zmq_recv (s, &msg, 0);
        assert (rc == 0);
        assert (zmq_msg_size (&msg) == message_size);
    }

    timeval end;
    rc = gettimeofday (&end, NULL);
    assert (rc == 0);

    end.tv_sec -= start.tv_sec;
    start.tv_sec = 0;

    elapsed = (end.tv_sec * 1000000 + end.tv_usec) -
        (start.tv_sec * 1000000 + start.tv_usec);

    throughput = (long long) message_count * 1000000 / elapsed;

    printf ("message size: %d [B]\n", (int) message_size);
    printf ("message count: %d\n", (int) message_count);
    printf ("mean throughput: %d [msg/s]\n", (int) throughput);

    return 0;
}