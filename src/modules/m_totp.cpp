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
#include "modules/hash.h"

class Base32
{
	static const std::string Base32Chars;

public:
	static std::string Encode(const std::string& input, size_t len = 0)
	{
		if (!len)
			len = input.length();

		size_t blocks = std::floor(len / 5);
		size_t rest = len % 5;

		std::vector<unsigned char> data(input.begin(), input.end());
		data.resize(len);

		if (rest)
		{
			data.resize(data.size() +  5 - rest);
			++blocks;
		}

		std::string ret;
		for (size_t i = 0; i < blocks; ++i)
		{
			ret += Base32Chars[data[i*5] >> 3];
			ret += Base32Chars[(data[i * 5] & 0x07) << 2 | (data[i * 5 + 1] >> 6)];
			ret += Base32Chars[(data[i * 5 + 1] & 0x3f) >> 1];
			ret += Base32Chars[(data[i * 5 + 1] & 0x01) << 4 | (data[i * 5 + 2] >> 4)];
			ret += Base32Chars[(data[i * 5 + 2] & 0x0f) << 1 | (data[i * 5 + 3] >> 7)];
			ret += Base32Chars[(data[i * 5 + 3] & 0x7f) >> 2];
			ret += Base32Chars[(data[i * 5 + 3] & 0x03) << 3 | (data[i * 5 + 4] >> 5)];
			ret += Base32Chars[(data[i * 5 + 4] & 0x1f)];
		}

		short padding =
			rest == 1 ? 6 :
			rest == 2 ? 3 :
			rest == 3 ? 3 :
			rest == 4 ? 1 : 0;

		ret = ret.substr(0, ret.length() - padding);
		ret.append(padding, '=');
		return ret;
	}

	static std::string Decode(const std::string& data)
	{
		std::string ret;
		ret.resize((data.length() * 5) / 8);

		size_t left = 0;
		size_t count = 0;

		unsigned int buffer = 0;
		for (std::string::const_iterator it = data.begin(); it != data.end(); ++it)
		{
			size_t val = Base32Chars.find(*it);
			if (val >= 32)
				continue;

			buffer <<= 5;
			buffer |= val;
			left += 5;
			if (left >= 8)
			{
				ret[count++] = (buffer >> (left - 8)) & 0xff;
				left -= 8;
			}
		}

		if (left)
		{
			buffer <<= 5;
			ret[count++] = (buffer >> (left - 3)) & 0xff;
		}

		ret.resize(count);
		return ret;
	}
};
const std::string Base32::Base32Chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");


class TOTPImplementation : public TOTPProvider
{
	dynamic_reference<HashProvider>& hash_prov;
	unsigned int& window;

	std::string Generate(const std::string secret, unsigned long time = 0)
	{
		if (!hash_prov)
			return "";

		std::vector<uint8_t> challenge(8);
		for (int i = 8; i--; time >>= 8)
			challenge[i] = time;

		std::string key = Base32::Decode(secret);
		std::string hash = hash_prov->hmac(key, std::string(challenge.begin(), challenge.end()));

		int offset = hash[hash_prov->out_size - 1] & 0xF;
		unsigned int truncatedHash = 0;
		for (int i = 0; i < 4; ++i)
		{
			truncatedHash <<= 8;
			truncatedHash |= (unsigned char)hash[offset + i];
		}

		truncatedHash &= 0x7FFFFFFF;
		truncatedHash %= 1000000;

		std::string ret = ConvToStr(truncatedHash);
		ret.insert(0, 6 - ret.length(), '0');
		return ret;
	}

 public:
	TOTPImplementation(Module* creator, dynamic_reference<HashProvider>& hash, unsigned int& wnd) : TOTPProvider(creator, "totp"), hash_prov(hash), window(wnd)
	{
	}

	bool Validate(const std::string& code, const std::string& secret)
	{
		if (code.length() != 6)
			return false;

		unsigned long time = (ServerInstance->Time() - 30 * window) / 30;
		unsigned long time_end = (ServerInstance->Time() + 30 * window) / 30;
		for (; time < time_end; ++time)
			if (Generate(secret, time) == code)
				return true;
		return false;
	}

	std::string MakeSecret() CXX11_OVERRIDE
	{
		std::string secret;
		secret.resize(10);
		for (uint8_t i = 0; i < 10; ++i)
			secret[i] = (uint8_t)ServerInstance->GenRandomInt(0xff);

		return Base32::Encode(secret, 10);
	}

	std::string Algorithm() CXX11_OVERRIDE
	{
		return hash_prov->name.substr(5);
	}

	bool IsEverythingWorkingAsIntended() CXX11_OVERRIDE
	{
		return hash_prov;
	}
};

class ModuleTOTP : public Module
{
	dynamic_reference<HashProvider> hash;
	unsigned int window;
	TOTPImplementation totp;

 public:
 	ModuleTOTP() : hash(this, "hash/sha256"), window(5), totp(this, hash, window)
 	{
 	}

 	void ReadConfig(ConfigStatus& status) CXX11_OVERRIDE
	{
		ConfigTag* tag = ServerInstance->Config->ConfValue("totp");
		window = tag->getInt("window", 5);
		hash.SetProvider("hash/" + tag->getString("hash", "sha256"));
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Provides TOTP for other modules", VF_VENDOR);
	}
};

MODULE_INIT(ModuleTOTP)
