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

#ifndef __ZMQ_DEVPOLL_HPP_INCLUDED__
#define __ZMQ_DEVPOLL_HPP_INCLUDED__

//  poller.hpp decides which polling mechanism to use.
#include "poller.hpp"
#if defined ZMQ_USE_DEVPOLL

#include <vector>

#include "fd.hpp"
#include "thread.hpp"
#include "poller_base.hpp"

namespace zmq
{

    //  Implements socket polling mechanism using the "/dev/poll" interface.

    class devpoll_t : public poller_base_t
    {
    public:

        typedef fd_t handle_t;

        devpoll_t ();
        ~devpoll_t ();

        //  "poller" concept.
        handle_t add_fd (fd_t fd_, struct i_poll_events *events_);
        void rm_fd (handle_t handle_);
        void set_pollin (handle_t handle_);
        void reset_pollin (handle_t handle_);
        void set_pollout (handle_t handle_);
        void reset_pollout (handle_t handle_);
        void start ();
        void stop ();

    private:

        //  Main worker thread routine.
        static void worker_routine (void *arg_);

        //  Main event loop.
        void loop ();

        //  File descriptor referring to "/dev/poll" pseudo-device.
        fd_t devpoll_fd;

        struct fd_entry_t
        {
            short events;
            struct i_poll_events *reactor;
            bool valid;
            bool accepted;
        };

        typedef std::vector <fd_entry_t> fd_table_t;
        fd_table_t fd_table;

        typedef std::vector <fd_t> pending_list_t;
        pending_list_t pending_list;

        //  Pollset manipulation function.
        void devpoll_ctl (fd_t fd_, short events_);

        //  If true, thread is in the process of shutting down.
        bool stopping;

        //  Handle of the physical thread doing the I/O work.
        thread_t worker;

        devpoll_t (const devpoll_t&);
        const devpoll_t &operator = (const devpoll_t&);
    };

    typedef devpoll_t poller_t;

}

#endif

#endif
