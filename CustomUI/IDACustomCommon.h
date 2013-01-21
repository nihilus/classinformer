
// ****************************************************************************
// File: IDACustomCommon.h
// Desc: Common IDA GUI customization support
//
// ****************************************************************************
#pragma once

// Include IDA headers before me..
#include <commctrl.h>

namespace IDACSTM
{
	// Return our IDA main HWND
	static HWND WINAPI GetIDAWindow(){	return((HWND) callui(ui_get_hwnd).vptr); }

	// Return TRUE IDA is the Qt version
	static BOOL WINAPI IsQtVersion()
	{		
		return(is_idaq());

		// non-Qt "TIdaWindow", Qt "QWidget"
		/*
		char szClass[max(sizeof("TIdaWindow"), sizeof("QWidget")) + 2]; szClass[0] = szClass[SIZESTR(szClass)] = 0;
		if(GetClassNameA(GetIDAWindow(), szClass, SIZESTR(szClass)))
		{
			return(qstrcmp(szClass, "QWidget") == 0);
		}
		return(TRUE);
		*/
	}
};
