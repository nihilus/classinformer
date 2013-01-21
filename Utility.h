
// ****************************************************************************
// File: Utility.h
// Desc: Utility stuff
//
// ****************************************************************************
#pragma once

#include "ContainersInl.h"

// Size of string with out terminator
#define SIZESTR(x) (sizeof(x) - 1)

#define ALIGN(_x_) __declspec(align(_x_))

#define NOVTABLE __declspec(novtable)

// Time 
typedef double TIMESTAMP;  // In fractional seconds
#define SECOND 1
#define MINUTE (60 * SECOND)
#define HOUR   (60 * MINUTE)
#define DAY    (HOUR * 24)

void Trace(const char *format, ...);
TIMESTAMP GetTimeStamp();
TIMESTAMP GetTimeStampLow();

// Sequential 32 bit flag serializer 
struct SBITFLAG
{
	inline SBITFLAG() : Index(0) {}
	inline UINT First(){ Index = 0; return(1 << Index++); }
	inline UINT Next(){ return(1 << Index++); }
	UINT Index;
};

// Get IDA 32 bit value with verification
template <class T> BOOL GetVerify32_t(ea_t eaPtr, T &rValue)
{
	// Location valid?
	if(getFlags(eaPtr))
	{
		// Get 32bit value
		rValue = (T) get_32bit(eaPtr);
		return(TRUE);
	}

	return(FALSE);
}