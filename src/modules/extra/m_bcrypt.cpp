/* $LinkerFlags: -lxcrypt */

#include "inspircd.h"
#include "hash.h"
#include <xcrypt.h>

class BCryptProvider : public HashProvider
{
 private:
	std::string Salt()
	{
		char entropy[16];
		for (unsigned int i = 0; i < sizeof(entropy); i++)
			entropy[i] = ServerInstance->GenRandomInt(0xFF);

		char salt[64];
		if (!crypt_gensalt_rn("$2a$", rounds, entropy, sizeof(entropy), salt, sizeof(salt)))
			return "";

		return salt;
	}

 public:
	unsigned int rounds;

	std::string sum(const std::string& data, const std::string salt)
	{
		if (salt.empty())
			return "";

		char hash[64];
		if (!crypt_rn(data.c_str(), salt.c_str(), hash, 64))
			return "";
		return hash;
	}

	std::string sum(const std::string& data)
	{
		return sum(data, Salt());
	}

	std::string sumIV(unsigned int* IV, const char* HexMap, const std::string &sdata)
	{
		return "";
	}

	bool Compare(const std::string& string, const std::string& hash)
	{
		std::string ret = sum(string, hash);
		if (ret.empty())
			return false;

		if (ret == hash)
			return true;
		return false;
	}

	BCryptProvider(Module* parent) : HashProvider(parent, "hash/bcrypt", 30, 64), rounds(10)
	{
	}
};

class ModuleBCrypt : public Module
{
	BCryptProvider bcrypt;

 public:
	ModuleBCrypt() : bcrypt(this)
	{
	}

	void init()
	{
		OnRehash(NULL);
		Implementation eventlist[] = { I_OnRehash,  I_OnPassCompare };
		ServerInstance->Modules->Attach(eventlist, this, sizeof(eventlist) / sizeof(Implementation));
		ServerInstance->Modules->AddService(bcrypt);
	}

	void OnRehash(User* user)
	{
		ConfigTag* conf = ServerInstance->Config->ConfValue("bcrypt");
		bcrypt.rounds = conf->getInt("rounds", 10);
	}

	ModResult OnPassCompare(Extensible* ex, const std::string &data, const std::string &input, const std::string &hashtype)
	{
		if ("hash/" + hashtype != "hash/bcrypt")
			return MOD_RES_PASSTHRU;

		if (bcrypt.Compare(input, data))
			return MOD_RES_ALLOW;
		return MOD_RES_DENY;
	}

	void Prioritize()
	{
		Module* mod = ServerInstance->Modules->Find("m_password_hash.so");
		ServerInstance->Modules->SetPriority(this, I_OnPassCompare, PRIORITY_BEFORE, mod);
	}

	~ModuleBCrypt()
	{
	}

	Version GetVersion()
	{
		return Version("Implements bcrypt hashing", VF_NONE);
	}
};

MODULE_INIT(ModuleBCrypt)
