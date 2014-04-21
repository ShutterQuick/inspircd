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
#include "modules/hash.h"

struct ProvSettings
{
	unsigned int dkey_length;
	unsigned int rounds;
	std::string salt;
};

class PBKDF2Provider : public HashProvider
{
	dynamic_reference<HashProvider>& provider;
	ProvSettings& ps;

	std::string PBKDF2(const std::string& pass, const std::string& salt)
	{
		size_t blocks = std::ceil((double)ps.dkey_length / provider->out_size);

		std::string output;
		for (size_t block = 1; block <= blocks; block++)
		{
			std::vector<char> salt_data(4);
			for (size_t i = 0; i < 4; i++)
				salt_data[i] = block >> (24 - i * 8) & 0x0F;

			std::string salt_block(salt_data.begin(), salt_data.begin() + 4);
			salt_block = salt + salt_block;

			std::string blockdata;
			std::string lasthash = blockdata = provider->HMAC(pass, salt_block);
			for (size_t iter = 1; iter < ps.rounds; iter++)
			{
				std::string tmphash = provider->HMAC(pass, lasthash);
				for (size_t i = 0; i < provider->out_size; i++)
					blockdata[i] ^= tmphash[i];

				lasthash = tmphash;
			}
			output += blockdata;
		}

		output = output.substr(0, ps.dkey_length);
		return output;
	}

 public:
	std::string Generate(const std::string& data, const HashProvider::HashType type)
	{
		std::string ret = PBKDF2(data, ps.salt);

		if (type == HashProvider::HASH_RAW)
			return ret;
		return BinToHex(ret);
	}

	std::string RAW(const std::string& raw)
	{
		return BinToHex(raw);
	}

	PBKDF2Provider(Module* parent, dynamic_reference<HashProvider>& prov, ProvSettings& p) :
		HashProvider(parent, "hash/pbkdf2-hmac-" + prov->name.substr(prov->name.find('/') + 1)), provider(prov), ps(p)
	{
		DisableAutoRegister();
	}
};

class ModulePBKDF2 : public Module
{
	struct ProvInfo
	{
		ProvSettings Ps;
		dynamic_reference<HashProvider> Ref;
		PBKDF2Provider Prov;

		ProvInfo(Module* m, const std::string& name) : Ref(m, name), Prov(m, Ref, Ps)
		{
		}
	};

	std::vector<ProvInfo*> provider_info;

 public:
	ModulePBKDF2()
	{
	}

	~ModulePBKDF2()
	{
		for (std::vector<ProvInfo*>::reverse_iterator it = provider_info.rbegin(); it != provider_info.rend(); ++it)
			delete *it;
	}

	void Prioritize() CXX11_OVERRIDE
	{
		OnLoadModule(NULL);
	}

	void OnLoadModule(Module* mod) CXX11_OVERRIDE
	{
		for (std::multimap<std::string, ServiceProvider*>::iterator i = ServerInstance->Modules->DataProviders.begin(); i != ServerInstance->Modules->DataProviders.end(); ++i)
		{
			HashProvider* hp = dynamic_cast<HashProvider*>(i->second);
			if (!hp)
				continue;

			for (std::vector<ProvInfo*>::iterator it = provider_info.begin(); it != provider_info.end(); ++it)
			{
				if (*(*it)->Ref == hp)
				{
					hp = NULL;
					break;
				}
			}

			if (!hp || hp->IsKDF())
				continue;

			ProvInfo* pi = new ProvInfo(this, hp->name);
			provider_info.push_back(pi);
			ServerInstance->Modules->AddService(pi->Prov);

			ConfigStatus cs;
			ReadConfig(cs);
		}
	}

	void OnUnloadModule(Module* mod) CXX11_OVERRIDE
	{
		for (std::vector<ProvInfo*>::reverse_iterator it = provider_info.rbegin(); it != provider_info.rend(); ++it)
		{
			if ((*it)->Ref->creator != mod)
				continue;

			provider_info.erase(--(it.base()));
			delete *it;
		}
	}

	void ReadConfig(ConfigStatus& status) CXX11_OVERRIDE
	{
		// First set the common values
		ConfigTag* tag = ServerInstance->Config->ConfValue("pbkdf2");
		unsigned int global_rounds = tag->getInt("rounds", 12288, 1);
		unsigned int global_dkey_length = tag->getInt("dkey_length", 32, 1, 1024);
		std::string global_salt = tag->getString("salt");
		for (std::vector<ProvInfo*>::iterator it = provider_info.begin(); it != provider_info.end(); ++it)
		{
			ProvInfo* pi = *it;
			pi->Ps.rounds = global_rounds;
			pi->Ps.dkey_length = global_dkey_length;
			pi->Ps.salt = global_salt;
		}

		// Then the specific values
		ConfigTagList tags = ServerInstance->Config->ConfTags("pbkdf2prov");
		unsigned short set_salt = 0;
		for (ConfigIter i = tags.first; i != tags.second; ++i)
		{
			std::string hash_name = i->second->getString("hash");
			for (std::vector<ProvInfo*>::iterator it = provider_info.begin(); it != provider_info.end(); ++it)
			{
				ProvInfo* pi = *it;
				if (pi->Ref->name != "hash/" + hash_name)
					continue;

				pi->Ps.rounds = i->second->getInt("rounds", global_rounds, 1);
				pi->Ps.dkey_length = i->second->getInt("dkey_length", global_dkey_length, 1, 1024);
				if (!(pi->Ps.salt = i->second->getString("salt", global_salt)).empty())
					++set_salt;
			}
		}

		if (global_salt.empty() && set_salt != provider_info.size())
			ServerInstance->SNO->WriteGlobalSno('a', "Salt not specified for all pbkdf2 providers");			
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Implements PBKDF2 hashing",VF_VENDOR);
	}
};

MODULE_INIT(ModulePBKDF2)
