/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2007 Dennis Friis <peavey@inspircd.org>
 *   Copyright (C) 2007 Robin Burchell <robin+git@viroteck.net>
 *   Copyright (C) 2004-2005, 2007 Craig Edwards <craigedwards@brainbox.cc>
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

/** Handle /SAJOIN
 */
class CommandSajoin : public Command
{
 public:
	CommandSajoin(Module* Creator) : Command(Creator,"SAJOIN", 1)
	{
		allow_empty_last_param = false;
		flags_needed = 'o'; Penalty = 0; syntax = "[<nick>] [prefix]<channel>";
		TRANSLATE2(TR_NICK, TR_TEXT);
	}

	CmdResult Handle (const std::vector<std::string>& parameters, User *user)
	{
		User* dest;
		std::string channelstring;

		if (parameters.size() > 1)
		{
			dest = ServerInstance->FindNick(parameters[0]);
			channelstring = parameters[1];
		}
		else
		{
			dest = user;
			channelstring = parameters[0];
		}

		if ((dest) && (dest->registered == REG_ALL))
		{
			if ((user == dest && !user->HasPrivPermission("users/sajoin/self", true)) ||
				(user != dest && !user->HasPrivPermission("users/sajoin/others", true)))
			{
				user->WriteNotice("*** You are not allowed to use sajoin on the user you tried");
				return CMD_FAILURE;
			}

			std::vector<PrefixMode*> pm;
			size_t hashpos = channelstring.find('#');
			std::string modestring = channelstring.substr(0, hashpos);
			std::string channel = channelstring.substr(hashpos);
			if (hashpos)
			{
				if (!user->HasPrivPermission("users/sajoin/modes", true))
				{
					user->WriteNotice("*** You are not allowed to specify modes for sajoin");
					return CMD_FAILURE;
				}

				ModeHandler* mh;
				std::string illegal_modes;
				std::string oper_modes;
				for (unsigned int i = 0; i < modestring.size(); i++)
				{
					if (illegal_modes.find(modestring[i]) != std::string::npos)
						continue;

					mh = ServerInstance->Modes->FindPrefix(modestring[i]);
					PrefixMode* tpm;
					if (mh)
						tpm = mh->IsPrefixMode();

					if (!mh || !tpm)
					{
						illegal_modes.push_back(modestring[i]);
						continue;
					}

					if (tpm->NeedsOper() && !user->HasModePermission(tpm->GetModeChar(), MODETYPE_USER))
					{
						oper_modes.push_back(modestring[i]);
						continue;
					}

					std::vector<PrefixMode*>::iterator it = std::find(pm.begin(), pm.end(), tpm);
					if (it == pm.end())				
						pm.push_back(tpm); 	
				}

				if (illegal_modes.size())
				{
					user->WriteNotice("*** The following modes are not valid prefix modes: " + illegal_modes);
					return CMD_FAILURE;
				}

				if (oper_modes.size())
				{
					user->WriteNotice("*** The following prefix modes requires the target to be an oper: " + oper_modes);
						return CMD_FAILURE;
				}
			}


			if (ServerInstance->ULine(dest->server))
			{
				user->WriteNumeric(ERR_NOPRIVILEGES, "%s :Cannot use an SA command on a u-lined client",user->nick.c_str());
				return CMD_FAILURE;
			}
			if (IS_LOCAL(user) && !ServerInstance->IsChannel(channel))
			{
				/* we didn't need to check this for each character ;) */
				user->WriteNotice("*** Invalid characters in channel name or name too long");
				return CMD_FAILURE;
			}

			/* For local users, we call Channel::JoinUser which may create a channel and set its TS.
			 * For non-local users, we just return CMD_SUCCESS, knowing this will propagate it where it needs to be
			 * and then that server will handle the command.
			 */
			LocalUser* localuser = IS_LOCAL(dest);
			if (localuser)
			{
				Channel* n = Channel::JoinUser(localuser, channel, true);
				if (n)
				{
					if (n->HasUser(dest))
					{
						ServerInstance->SNO->WriteToSnoMask('a', user->nick+" used SAJOIN to make "+dest->nick+" join " + modestring + channel);

						irc::modestacker modestack(true);
						for (std::vector<PrefixMode*>::iterator it = pm.begin(); it != pm.end(); it++)
							modestack.Push((*it)->GetModeChar(), dest->nick);

						parameterlist stackresult;
						stackresult.push_back(n->name);
						while (modestack.GetStackedLine(stackresult))
						{
							ServerInstance->Modes->Process(stackresult, ServerInstance->FakeClient);
							stackresult.erase(stackresult.begin() + 1, stackresult.end());
						}

						return CMD_SUCCESS;
					}
					else
					{
						user->WriteNotice("*** Could not join "+dest->nick+" to "+channel+" (User is probably banned, or blocking modes)");
						return CMD_FAILURE;
					}
				}
				else
				{
					user->WriteNotice("*** Could not join "+dest->nick+" to "+channel);
					return CMD_FAILURE;
				}
			}
			else
			{
				ServerInstance->SNO->WriteToSnoMask('a', user->nick+" sent remote SAJOIN to make "+dest->nick+" join "+channel);
				return CMD_SUCCESS;
			}
		}
		else
		{
			user->WriteNotice("*** No such nickname "+parameters[0]);
			return CMD_FAILURE;
		}
	}

	RouteDescriptor GetRouting(User* user, const std::vector<std::string>& parameters)
	{
		User* dest = ServerInstance->FindNick(parameters[0]);
		if (dest)
			return ROUTE_OPT_UCAST(dest->server);
		return ROUTE_LOCALONLY;
	}
};

class ModuleSajoin : public Module
{
	CommandSajoin cmd;
 public:
	ModuleSajoin()
		: cmd(this)
	{
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Provides command SAJOIN to allow opers to force-join users to channels", VF_OPTCOMMON | VF_VENDOR);
	}
};

MODULE_INIT(ModuleSajoin)
