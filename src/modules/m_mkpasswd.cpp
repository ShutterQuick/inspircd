/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2009-2010 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2008 Thomas Stagner <aquanight@inspircd.org>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "inspircd.h"
#include "modules/hash.h"

/* Handle /MKPASSWD
 */
class CommandMkpasswd : public Command
{
 public:
	CommandMkpasswd(Module* Creator) : Command(Creator, "MKPASSWD", 2)
	{
		syntax = "<algorithm> <password>";
		Penalty = 5;
	}

	void MakeHash(User* user, const std::string& algo, const std::string& stuff)
	{
		if (algo.substr(0,5) == "hmac-")
		{
			std::string type = algo.substr(5);
			HashProvider* hp = ServerInstance->Modules->FindDataService<HashProvider>("hash/" + type);
			if (!hp)
			{
				user->WriteNotice("Unknown hash type");
				return;
			}
			std::string salt = ServerInstance->GenRandomStr(6, false);
			std::string target = hp->HMAC(salt, stuff);
			if (!hp->out_size || !hp->block_size)
			{
				user->WriteNotice(algo + " does not support HMAC");
				return;
			}

			std::string str = BinToBase64(salt) + "$" + BinToBase64(target, NULL, 0);

			user->WriteNotice(algo + " hashed password for " + stuff + " is " + str);
			return;
		}
		HashProvider* hp = ServerInstance->Modules->FindDataService<HashProvider>("hash/" + algo);
		if (hp)
		{
			/* Now attempt to generate a hash */
			user->WriteNotice(algo + " hashed password for " + stuff + " is " + hp->Generate(stuff));
		}
		else
		{
			user->WriteNotice("Unknown hash type");
		}
	}

	CmdResult Handle (const std::vector<std::string>& parameters, User *user)
	{
		MakeHash(user, parameters[0], parameters[1]);

		return CMD_SUCCESS;
	}
};

class ModuleMKPasswd : public Module
{
	CommandMkpasswd cmd;
 public:

	ModuleMKPasswd() : cmd(this)
	{
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Allows for hashed oper passwords",VF_VENDOR);
	}
};

MODULE_INIT(ModuleMKPasswd)
