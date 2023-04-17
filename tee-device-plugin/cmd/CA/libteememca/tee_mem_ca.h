#ifndef __TEE_MEM_CA_H__
#define __TEE_MEM_CA_H__

// return the free memory of tee, unit is KB
long long GetTeeFreeMem(void);
// return the Capacity memory(physical memory - kernal ) of tee, unit is KB
long long GetTeeCapacityMem(void);

#endif