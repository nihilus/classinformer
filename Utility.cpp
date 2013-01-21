
// ****************************************************************************
// File: Utility.cpp
// Desc: Utility stuff
//
// ****************************************************************************
#include "stdafx.h"


// Integer to to double seconds
#define I2TIME(_int) ((double) (_int) * (double) ((double) 1.0 / (double) 1000.0))

// ==== Data ====
static ALIGN(16) double s_fTimeStampHolder = 0;
static DWORD s_dwLastTimeRead = 0; 
extern BOOL  bDebugOutput;

// ****************************************************************************
// Func: GetTimeSamp()
// Desc: Get high precision elapsed seconds
//
// ****************************************************************************
TIMESTAMP GetTimeStamp() 
{
	LARGE_INTEGER tLarge;
	QueryPerformanceCounter(&tLarge);

	static ALIGN(16) TIMESTAMP s_ClockFreq;
	if(s_ClockFreq == 0.0)
	{
		// Set the minimal timeBeginPeriod()
		// The best ms accuracy of both "timeGetTime()" and "Sleep()"
		int iPeriod = 1;
		while(iPeriod < 20)
		{
			if(timeBeginPeriod(iPeriod) == TIMERR_NOERROR)
				break;
		};

		LARGE_INTEGER tLarge;
		QueryPerformanceFrequency(&tLarge);
		s_ClockFreq = (TIMESTAMP) tLarge.QuadPart; 
	}
	
	return((TIMESTAMP) tLarge.QuadPart / s_ClockFreq);
}


// Get delta time stamp, lower precision but much less overhead
TIMESTAMP GetTimeStampLow()
{
	// Time with ms precision
	DWORD dwTime = timeGetTime();	

	// Get delta time
	DWORD dwDelta;
	if(dwTime >= s_dwLastTimeRead)
		dwDelta = (dwTime - s_dwLastTimeRead);
	else
		// Rolled over.. (happens every ~49.71 days of computer time)
		dwDelta = (s_dwLastTimeRead - dwTime);

	s_dwLastTimeRead = dwTime;
	s_fTimeStampHolder += I2TIME(dwDelta);
	return(s_fTimeStampHolder);
}

// ****************************************************************************
// Func: Trace()
// Desc: Output text to debugger screen
//
// ****************************************************************************
void Trace(const char *format, ...)
{
	if(bDebugOutput)
	{
		if(format)
		{
			// Format string
			va_list vl;
			char str[4096]; str[SIZESTR(str)] = 0;
			va_start(vl, format);
			_vsntprintf(str, (sizeof(str) - 1), format, vl);
			va_end(vl);

			// Output it
			OutputDebugString(str);
		}
	}
}
