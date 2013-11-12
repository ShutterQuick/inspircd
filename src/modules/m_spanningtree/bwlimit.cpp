#include "bwlimit.h"
#include "timer.h"
#include "treeserver.h"
#include "link.h"

void DataLimiter::Recv(size_t bytes)
{
	if (Enabled)
		DataPoints[0].Recv += bytes;
}

void DataLimiter::Send(size_t bytes)
{
	if (Enabled)
		DataPoints[0].Send += bytes;
}

DataLimiter::CounterStruct DataLimiter::GetRate(unsigned int minutes)
{
	CounterStruct ret;
	for (unsigned int i = 0; i < minutes; i++)
	{
		ret.Recv += DataPoints[i].Recv;
		ret.Send += DataPoints[i].Send;
	}

	ret.Recv /= minutes * 60;
	ret.Send /= minutes * 60;
	return ret;
}

bool DataLimiter::IsDisabled()
{
	for (unsigned int i = 0; i < 3; i++)
		if (Limits.Hard[i] || Limits.Soft[i])
			return (Enabled = true);
	return (Enabled = false);
}

bool DataLimiter::Tick(time_t time)
{
	static unsigned int counter = 0;

	if (!Server || !Enabled)
		return true;

	counter++;

	unsigned int Interval[3];
	Interval[0] = 5;
	Interval[1] = 15;
	Interval[2] = 60;

	CounterStruct cs;
	for (unsigned int i = 0; i < 3; i++)
	{
		if (counter % Interval[i] != 0)
			continue;

		cs = GetRate(Interval[i]);
		if (Limits.Hard[i] && (cs.Recv > Limits.Hard[i] || cs.Send > Limits.Hard[i]))
		{
			ServerInstance->SNO->WriteGlobalSno('T', "Warning: S2S %s <-> %s has exceeded it's hard limit BW of %fkbps the last %u minutes - Connection between servers severed. Actual use %fkbps", ServerInstance->Config->ServerName.c_str(), Server->GetName().c_str(), ((float)Limits.Hard[i] / 1000), Interval[i], ((float)((cs.Recv > cs.Send ? cs.Recv : cs.Send) / 1000)));
			Server->GetSocket()->Squit(Server, "S2S-flood");
			break;
		}

		if (Limits.Soft[i] && (cs.Recv > Limits.Soft[i] || cs.Send > Limits.Soft[i]))
		{
			ServerInstance->SNO->WriteGlobalSno('T', "Warning: S2S %s <-> %s has exceeded it's soft limit BW of %fkbps the last %u minutes. Actual use: %fkbps", ServerInstance->Config->ServerName.c_str(), Server->GetName().c_str(), ((float)Limits.Soft[i] / 1000), Interval[i], ((float)((cs.Recv > cs.Send ? cs.Recv : cs.Send) / 1000)));
			break;
		}
	}

	DataPoints.pop_back();
	DataPoints.push_front(CounterStruct());

	return true;
}

void DataLimiter::SetLink(Link* link)
{
	Limits = link->DCLimits;
	IsDisabled();
}

DataLimits& DataLimiter::getBlankLimits()
{
	static DataLimits dat;
	return dat;
}

DataLimiter::DataLimiter(TreeServer*& server) : Timer(60, ServerInstance->Time(), true), DataPoints(60), Server(server), Limits(getBlankLimits())
{
	ServerInstance->Timers->AddTimer(this);
}

DataLimiter::~DataLimiter()
{
	ServerInstance->Timers->DelTimer(this);
}
