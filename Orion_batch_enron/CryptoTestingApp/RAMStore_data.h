#pragma once
#include "../common/data_type2.h"
#include <map>
#include <array>

class RAMStore
{
	std::vector<BUCKET> data; // data is a collection of BUCKET
	size_t size;
	size_t emptyNodes; // should we init the 'emptyNodes' as leaf

public:
	RAMStore(size_t num);
	~RAMStore();

	BUCKET Read(size_t pos);
	void Write(size_t pos, BUCKET b);

	size_t GetBucketCount();
	void ReduceEmptyNumbers();
	size_t GetEmptySize();
};
