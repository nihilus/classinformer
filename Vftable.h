
// ****************************************************************************
// File: Vftable.h
// Desc: Vftable support
//
// ****************************************************************************
#pragma once

namespace VFTABLE
{
	// vftable info container
	struct tINFO
	{
		ea_t eaStart;
		ea_t eaEnd;
		asize_t uMethods;
		char szName[MAXSTR];
	};

	BOOL GetTableInfo(ea_t eaAddress, tINFO &rtInfo);
	
	// Returns TRUE if mangled name indicates vftable
	inline BOOL IsValidByName(LPCSTR pszName){ return(*((PDWORD) pszName) == 0x375F3F3F /*"??_7"*/); }

	// Identify and name common member functions
	void ProcessMembers(LPCTSTR lpszName, ea_t eaStart, ea_t eaEnd);
}
