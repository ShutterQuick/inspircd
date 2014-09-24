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


#pragma once

#include "inspircd.h"

class TOTPProvider : public DataProvider
{
 public:
	TOTPProvider(Module* creator, const std::string& name) : DataProvider(creator, "totp/" + name)
	{
	}

	/** Validate the 
	 * @param The code to validate
	 * @param The secret we want to validate the token for
	 * Leave empty for default or specify e.g. sha256.
	 * @return Returns true if the validation is OK, or false if it's not
	 */
	virtual bool Validate(const std::string& code, const std::string& secret) = 0;

	/** Generate a secret
	 * @return The secret as a base32 encoded string
	 */
	virtual std::string MakeSecret() = 0;

	/** What algorithm are we using?
	 * @return A string containing the algorithm in use - can be sha256, sha1 and md5
	 */
	virtual std::string Algorithm() = 0;

	/** As the provider is not unloaded when 
	 * the hashing provider it depends on isn't available
	 * we need to check if it can function before calling it.
	 * @return true if everything is OK, false if it isn't
	 */
	virtual bool IsEverythingWorkingAsIntended() = 0;
};
