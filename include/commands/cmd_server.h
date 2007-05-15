/*       +------------------------------------+
 *       | Inspire Internet Relay Chat Daemon |
 *       +------------------------------------+
 *
 *  InspIRCd is copyright (C) 2002-2007 ChatSpike-Dev.
 *                       E-mail:
 *                <brain@chatspike.net>
 *                <Craig@chatspike.net>
 *
 * Written by Craig Edwards, Craig McLure, and others.
 * This program is free but copyrighted software; see
 *            the file COPYING for details.
 *
 * ---------------------------------------------------
 */

#ifndef __CMD_SERVER_H__
#define __CMD_SERVER_H__

// include the common header files

#include "users.h"
#include "channels.h"

/** Handle /SERVER
 */
class cmd_server : public command_t
{
 public:
        cmd_server (InspIRCd* Instance) : command_t(Instance,"SERVER",0,0) { }
        CmdResult Handle(const char** parameters, int pcnt, userrec *user);
};

#endif
