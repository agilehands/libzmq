/*
    Copyright (c) 2011 Martin Lucina <mato@kotelna.sk>
    Copyright (c) 2011 Other contributors as noted in the AUTHORS file

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

#include "dns_resolver.h"

#include "../foreign/dns/dns.c"

#include <stdlib.h>

int dns_resolve_in_txt (const char *query_, char **txt_)
{
    int error = 0, found = 0;
    struct dns_options     *options = dns_opts ();
    struct dns_resolver    *resolver;
    struct dns_packet      *answer;
    struct dns_rr          rr;
    struct dns_txt         txt;
    enum dns_rcode         rcode;

    resolver = dns_res_stub (options, &error);
    if (!resolver)
        return error;
    
    error = dns_res_submit (resolver, query_, DNS_T_TXT, DNS_C_IN);
    if (error)
        goto out;

    while ((error = dns_res_check (resolver))) {
        if (error != EAGAIN)
            goto out;
        if (dns_res_elapsed (resolver) > 30) {
            error = ETIMEDOUT;
            goto out;
        }
        dns_res_poll (resolver, 1);
    }

    answer = dns_res_fetch (resolver, &error);
    if (error)
        goto out;
    rcode = dns_header (answer)->rcode;
    switch (rcode) {
        case DNS_RC_NOERROR:
            break;
        case DNS_RC_NXDOMAIN:
            error = ESRCH;
            goto out;
        case DNS_RC_FORMERR:
            error = EINVAL;
            goto out;
        default:
            error = EIO;
            goto out;
    }

    found = dns_rr_grep (&rr, 1, 
        dns_rr_i_new (answer, 
            .section = DNS_S_ANSWER, 
            .type    = DNS_T_TXT,
            .class   = DNS_C_IN),
        answer, &error);
    if (error)
        goto out;
    if (!found) {
        error = ESRCH;
        goto out;
    }

    error = dns_txt_parse (dns_txt_init (&txt, DNS_TXT_MINDATA), &rr, answer);
    if (error)
        goto out;
    *txt_ = malloc (txt.len + 1);
    assert (*txt_);
    memcpy (*txt_, txt.data, txt.len);
    (*txt_)[txt.len] = 0;
    free (answer);

out:
    dns_res_close (resolver);
    return error;
}

