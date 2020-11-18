#include "RAMStore_data.h"
#include <iostream>
// #include "ORAM.hpp"
using namespace std;

RAMStore::RAMStore(size_t count)
		: data(count), emptyNodes(count)
{
}

RAMStore::~RAMStore()
{
}

BUCKET RAMStore::Read(size_t pos)
{
	return data.at(pos);
}

void RAMStore::Write(size_t pos, BUCKET b)
{
	data[pos] = b;
}

size_t RAMStore::GetBucketCount()
{
	return data.size();
}

void RAMStore::ReduceEmptyNumbers()
{
	emptyNodes--;
}

size_t RAMStore::GetEmptySize()
{
	return emptyNodes;
}
