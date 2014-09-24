/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2014 Daniel Vassdal <shutter@canternet.org>
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
#include "modules/totp.h"

class CommandTOTP : public Command
{
	dynamic_reference<TOTPProvider>& totp;

	void ShowCode(User* user, const std::string& secret, const std::string& label = "")
	{	
		const std::string url = "https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2F"
			+ ServerInstance->Config->Network + (!label.empty() ? "%20(" + label + ")" : "") + "%3Falgorithm%3D"
			+ totp->Algorithm() + "%26secret%3D" + secret;

		user->WriteNotice("Secret: " + secret);
		user->WriteNotice("Algorithm: " + totp->Algorithm());
		user->WriteNotice("QR Code: " + url);
	}

	void GenerateCode(User* user, const std::string& label = "")
	{
		user->WriteNotice("Generated TOTP:" + (!label.empty() ? " for" + label : "") + ":");
		ShowCode(user, totp->MakeSecret(), label);
	}

public:
	CommandTOTP(Module* Creator, dynamic_reference<TOTPProvider>& otp) : Command(Creator, "TOTP", 0), totp(otp)
	{
		syntax = "<label|code>";
		flags_needed = 'o';
	}

	CmdResult Handle (const std::vector<std::string>& parameters, User *user)
	{
		if (!totp || !totp->IsEverythingWorkingAsIntended())
		{
			user->WriteNotice("No TOTP provider is loaded.");
			return CMD_SUCCESS;
		}

		if (parameters.empty())
		{
			GenerateCode(user);
			return CMD_SUCCESS;
		}

		if (parameters[0].length() == 6 && ConvToInt(parameters[0]))
		{
			std::string secret;
			if (!user->oper->oper_block->readString("totpsecret", secret))
				return CMD_SUCCESS;

			if (!totp->Validate(parameters[0], secret))
			{
				user->WriteNotice("TOTP not valid: " + parameters[0]);
				return CMD_FAILURE;
			}

			std::string uname;
			user->oper->oper_block->readString("name", uname);
			user->WriteNotice("Fetched your TOTP secret from config:");
			ShowCode(user, secret, uname);
		}
		else
			GenerateCode(user, parameters[0]);

		return CMD_SUCCESS;
	}
};

class ModuleTOTP : public Module
{
	dynamic_reference<TOTPProvider> totp;
	CommandTOTP cmd;

 public:
	ModuleTOTP() : totp(this, "totp/totp"), cmd(this, totp)
	{
	}

	ModResult OnPreCommand(std::string &command, std::vector<std::string> &parameters, LocalUser *user, bool validated, const std::string &original_line) CXX11_OVERRIDE
	{
		if (!validated || command != "OPER" || parameters.size() <= 1 || !totp || !totp->IsEverythingWorkingAsIntended())
			return MOD_RES_PASSTHRU;

		const ServerConfig::OperIndex::const_iterator it = ServerInstance->Config->oper_blocks.find(parameters[0]);
		if (it == ServerInstance->Config->oper_blocks.end())
			return MOD_RES_PASSTHRU;

		OperInfo* info = it->second;

		std::string secret;
		if (!info->oper_block->readString("totpsecret", secret))
			return MOD_RES_PASSTHRU;

		size_t pos = parameters[1].rfind(' ');
		if (pos == std::string::npos)
		{
			user->WriteNumeric(491, "%s :This oper login requires a TOTP token.", user->nick.c_str());
			return MOD_RES_DENY;
		}

		std::string otp = parameters[1].substr(pos + 1);
		parameters[1].erase(pos);

		if (totp->Validate(otp, secret))
			return MOD_RES_PASSTHRU;

		user->WriteNumeric(491, "%s :Invalid oper credentials",user->nick.c_str());
		user->CommandFloodPenalty += 10000;
		return MOD_RES_DENY;			
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Enables two factor authentification for oper blocks", VF_VENDOR);
	}
};

MODULE_INIT(ModuleTOTP)
