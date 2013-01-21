
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER       0x0502 // WinXP++    
#define _WIN32_WINNT 0x0502

#include <windows.h>
#include <time.h>
#include <mmsystem.h>
#include <tchar.h>
#include <math.h>
#include <crtdbg.h>
#include <intrin.h>

#pragma intrinsic(memset, memcpy, strcat, strcmp, strcpy, strlen, abs, fabs, labs, atan, atan2, tan, sqrt, sin, cos)


// IDA libs
//#define __NOT_ONLY_PRO_FUNCS__
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <ua.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include <funcs.hpp>
#include <search.hpp>
#include <kernwin.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <demangle.hpp>
#include <xref.hpp>
#include <typeinf.hpp>
#include <enum.hpp>
#include <struct.hpp>
#include <nalt.hpp>

#include "Utility.h"

#define MY_VERSION MAKEWORD(6, 1) // Low, high. Convention: 0 to 99