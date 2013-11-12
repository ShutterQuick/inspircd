#pragma once

#include "inspircd.h"

class Timer;
class TreeServer;
class Link;

struct DataLimits
{
	size_t Hard[3];
	size_t Soft[3];

	DataLimits()
	{
		memset(Hard, 0, sizeof(Hard));
		memset(Soft, 0, sizeof(Soft));
	}

	DataLimits(
		size_t hard5, size_t hard15, size_t hard60,
		size_t soft5, size_t soft15, size_t soft60
	)
	{
		Hard[0] = hard5;
		Hard[1] = hard15;
		Hard[2] = hard60;

		Soft[0] = soft5;
		Soft[1] = soft15;
		Soft[2] = soft60;
	}		
};

class DataLimiter : public Timer
{
 public:
	struct CounterStruct
	{
		size_t Recv;
		size_t Send;

		CounterStruct() : Recv(0), Send(0)
		{
		}
	};

 private:
	std::deque<CounterStruct> DataPoints;
	TreeServer*& Server;
	DataLimits& Limits;

	static DataLimits& getBlankLimits();
	bool IsDisabled();
	bool Enabled;
 public:
	void Send(size_t bytes);
	void Recv(size_t bytes);

	CounterStruct GetRate(unsigned int minutes);
	static void SetLimits(size_t[3], size_t[3]);
	bool Tick(time_t time);
	void SetLink(Link* link);
	DataLimiter(TreeServer*& server);
	~DataLimiter();
};

