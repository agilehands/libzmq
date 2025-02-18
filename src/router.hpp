/*
    Copyright (c) 2007-2011 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_ROUTER_HPP_INCLUDED__
#define __ZMQ_ROUTER_HPP_INCLUDED__

#include <map>
#include <deque>

#include "socket_base.hpp"
#include "session_base.hpp"
#include "stdint.hpp"
#include "msg.hpp"
#include "fq.hpp"

namespace zmq
{

    class router_t :
        public socket_base_t
    {
    public:

        router_t (class ctx_t *parent_, uint32_t tid_);
        ~router_t ();

        //  Overloads of functions from socket_base_t.
        void xattach_pipe (class pipe_t *pipe_);
        int xsend (class msg_t *msg_, int flags_);
        int xrecv (class msg_t *msg_, int flags_);
        bool xhas_in ();
        bool xhas_out ();
        void xread_activated (class pipe_t *pipe_);
        void xwrite_activated (class pipe_t *pipe_);
        void xterminated (class pipe_t *pipe_);

    protected:

        //  Rollback any message parts that were sent but not yet flushed.
        int rollback ();

    private:

        //  Fair queueing object for inbound pipes.
        fq_t fq;

        //  Have we prefetched a message.
        bool prefetched;

        //  Holds the prefetched message.
        msg_t prefetched_msg;

        //  If true, more incoming message parts are expected.
        bool more_in;

        struct outpipe_t
        {
            class pipe_t *pipe;
            bool active;
        };

        //  Outbound pipes indexed by the peer IDs.
        typedef std::map <uint32_t, outpipe_t> outpipes_t;
        outpipes_t outpipes;

        //  The pipe we are currently writing to.
        class pipe_t *current_out;

        //  If true, more outgoing message parts are expected.
        bool more_out;

        //  Peer ID are generated. It's a simple increment and wrap-over
        //  algorithm. This value is the next ID to use (if not used already).
        uint32_t next_peer_id;

        //  Commands to be delivered to the user.
        struct pending_command_t
        {
            uint8_t cmd;
            uint32_t peer;
        };
        typedef std::deque <pending_command_t> pending_commands_t;
        pending_commands_t pending_commands;

        router_t (const router_t&);
        const router_t &operator = (const router_t&);
    };

    class router_session_t : public session_base_t
    {
    public:

        router_session_t (class io_thread_t *io_thread_, bool connect_,
            class socket_base_t *socket_, const options_t &options_,
            const char *protocol_, const char *address_);
        ~router_session_t ();

    private:

        router_session_t (const router_session_t&);
        const router_session_t &operator = (const router_session_t&);
    };

}

#endif
