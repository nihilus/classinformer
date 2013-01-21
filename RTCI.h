
// ****************************************************************************
// File: RTCI.h 
// Desc: MFC Run Time Class Information
//
// ****************************************************************************
#pragma once

/*
	http://msdn.microsoft.com/en-us/library/fych0hw6(VS.80).aspx
*/

namespace RTCI
{	
	// From <afx.h>
	// RTCI type
	#pragma pack(push, 1)
	struct NOVTABLE CRuntimeClass
	{
		LPCSTR  m_lpszClassName;			// 00 Name of class/struct
		int     m_nObjectSize;				// 04 Object size
		UINT    m_wSchema;					// 08 0xFFFF "schema number of the loaded class"
		PVOID   m_pfnCreateObject;			// 0C Optional ctor "CObject* (PASCAL* m_pfnCreateObject)();"
		CRuntimeClass *m_pfnGetBaseClass;	// 10 Optional base class		
		CRuntimeClass *m_pNextClass;		// 14 Linked list of registered classes 
		PVOID   m_pClassInit;				// 18 "const AFX_CLASSINIT* m_pClassInit;"
		// pszName is usually follows..

		static LPCTSTR GetName(CRuntimeClass *ptRTCI, LPSTR lpszBuffer, int iSize);
		static void    DoStruct(CRuntimeClass *ptRTCI);
	};
	#pragma pack(pop)

	void CreateStructDefs();	
	BOOL IsValid(ea_t eaVftable);
	void ProcessVftable(ea_t eaVftable, ea_t eaEnd);
};