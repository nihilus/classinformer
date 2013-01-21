
// ****************************************************************************
// File: RTCI.cpp
// Desc: MFC Run Time Class Information
//
// ****************************************************************************
#include "stdafx.h"
#include "Core.h"
#include "RTCI.h"
#include "Vftable.h"

// Get or create an IDA struct
#define ADD_STRUCT(ID, NAME, COMMENT)\
{\
	ptStruct = NULL;\
	ID = get_struc_id(NAME);\
	if(ID == BADADDR)\
		ID = add_struc(BADADDR, NAME);\
	if(ID != BADADDR)\
		ptStruct = get_struc(ID);\
	if(ptStruct)\
	{\
		del_struc_members(ptStruct, 0, MAXADDR);\
		set_struc_cmt(ID, COMMENT, true);\
	}\
	else\
	msg(" ** \"" NAME "\" create failed! **\n");\
}

// Add structure member macro
#define ADD_MEMBER(pSTRUCT, FLAG, MT, TYPE, MEMBER)\
{\
	TYPE _tTYPE;\
	if(add_struc_member(pSTRUCT, #MEMBER, offsetof(TYPE, MEMBER), FLAG, MT, sizeof(_tTYPE.MEMBER)) != 0)\
		msg(" ** ADD_MEMBER(): %s failed! %d, %d **\n", #MEMBER, offsetof(TYPE, MEMBER), sizeof(_tTYPE.MEMBER));\
}

// Base class hierarchy list
struct tBCInfo : public Container::NodeEx<Container::ListHT, tBCInfo>
{
	tBCInfo(LPSTR pszName, UINT uSize)
	{ 		
		qstrncpy(m_szName, pszName, SIZESTR(m_szName));
        m_szName[SIZESTR(m_szName)] = 0;
		m_uSize = uSize;		
	}

	static PVOID __cdecl operator new(size_t size) { return(qalloc(size)); };
	static void __cdecl operator delete(PVOID _Ptr){ qfree(_Ptr); }

	char m_szName[MAXSTR];	
	UINT m_uSize;
};

namespace RTCI
{
	typedef Container::ListEx<Container::ListHT, tBCInfo> BCInfoList;

	void GetBCInfo(CRuntimeClass *ptRTCI, BCInfoList &rList);
};


// ==== Data ===
static tid_t s_RTCI_ID = 0;

// Add RTTI structures to IDA
void RTCI::CreateStructDefs()
{
	// Add RTCI structure type
	struc_t *ptStruct;
	ADD_STRUCT(s_RTCI_ID, "RTCI", "MFC \"Run Time Class Information\" (Class Informer)");
	if(ptStruct)
	{		
		// Member type info for 32bit offset types
		typeinfo_t mtoff = {0};
		mtoff.ri.flags  = REF_OFF32;
		mtoff.ri.target = BADADDR;

		ADD_MEMBER(ptStruct, (offflag()|dwrdflag()), &mtoff, CRuntimeClass, m_lpszClassName); 
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, CRuntimeClass, m_nObjectSize);
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, CRuntimeClass, m_wSchema);
		ADD_MEMBER(ptStruct, (offflag()|dwrdflag()), &mtoff, CRuntimeClass, m_pfnCreateObject);
		ADD_MEMBER(ptStruct, (offflag()|dwrdflag()), &mtoff, CRuntimeClass, m_pfnGetBaseClass);
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, CRuntimeClass, m_pNextClass);
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, CRuntimeClass, m_pClassInit);
	}
}

// Returns TRUE if vftable uses valid RTCI
BOOL RTCI::IsValid(ea_t eaVftable)
{
	ea_t eaFirstMethod;
	if(GetVerify32_t(eaVftable, eaFirstMethod))
	{
		// First methods will be a simple function that returns the RTCI* in eax
		// "mov xx, offset xxx"?
		LPCTSTR pszLine = GetDisasmText(eaFirstMethod);
		if((*((PUINT) pszLine) == 0x20766F6D /*"mov "*/) && (strstr(pszLine+4, "eax, offset ") != NULL))
		{
			CRuntimeClass *ptRTCI;
			if(GetVerify32_t(eaFirstMethod+1, ptRTCI))
			{	
				//Output(" P: %08X\n", ptRTCI);

				// First field should be a pointer to the name string
				LPCTSTR lpszName;
				if(GetVerify32_t((ea_t) &ptRTCI->m_lpszClassName, lpszName))
				{
					if(isASCII(getFlags((ea_t) lpszName)))
					{						
						char szName[MAXSTR];
						szName[0] = szName[MAXSTR-1] = 0;
						if(CRuntimeClass::GetName(ptRTCI, szName, SIZESTR(szName)))
						{
							//Output(" Name: \"%s\"\n", szName);

							UINT uFlag;
							if(GetVerify32_t((ea_t) &ptRTCI->m_wSchema, uFlag))
							{
								//Output("  Flag: %08X\n", uFlag);
								return(uFlag == 0xFFFF);
							}
						}
					}
				}
			}
		}
	}

	return(FALSE);
}


// Get type name from RTCI struct
// Assumes RTCI struct is valid
LPCTSTR RTCI::CRuntimeClass::GetName(CRuntimeClass *ptRTCI, LPSTR lpszBuffer, int iSize)
{
	lpszBuffer[0] = lpszBuffer[iSize - 1] = 0;

	LPCTSTR lpszName;
	if(GetVerify32_t((ea_t) &ptRTCI->m_lpszClassName, lpszName))
	{		
		int iLen = get_max_ascii_length((ea_t) lpszName, ASCSTR_TERMCHR, true);
		if(iLen > 0)
		{		
			if(iLen > iSize) iLen = iSize;
			if(get_ascii_contents((ea_t) lpszName, iLen, ASCSTR_TERMCHR, lpszBuffer, iSize))		
				return(lpszBuffer);		
		}	
	}
	
	return(NULL);
}


// Set structs in class info hierarchy
void RTCI::CRuntimeClass::DoStruct(CRuntimeClass *ptRTCI)
{
	if(ptRTCI)
	{		
		flags_t Flags = getFlags((ea_t) ptRTCI);
		
		// Get name
		char szName[MAXSTR];
		szName[0] = szName[MAXSTR-1] = 0;
		CRuntimeClass::GetName(ptRTCI, szName, SIZESTR(szName));

		// Fix name in IDA
		int iNameLen = (strlen(szName) + 1);		
		SetUnknown((ea_t) &ptRTCI->m_lpszClassName, iNameLen);	
		doASCI((ea_t) &ptRTCI->m_lpszClassName, iNameLen);

		// Set struct		
		//if(!isStruct(Flags)) // If it's already a struct, skip it.
		if(bPlaceStructs)
		{
			#define PutDword(ea) doDwrd(ea, sizeof(DWORD))

			ea_t ea = (ea_t) ptRTCI;
			SetUnknown(ea, sizeof(CRuntimeClass));			
			PutDword(ea + offsetof(CRuntimeClass, m_lpszClassName));
			PutDword(ea + offsetof(CRuntimeClass, m_nObjectSize));
			PutDword(ea + offsetof(CRuntimeClass, m_wSchema));
			PutDword(ea + offsetof(CRuntimeClass, m_pfnCreateObject));
			PutDword(ea + offsetof(CRuntimeClass, m_pfnGetBaseClass));
			PutDword(ea + offsetof(CRuntimeClass, m_pNextClass));
			PutDword(ea + offsetof(CRuntimeClass, m_pClassInit));
			doStruct(ea, sizeof(CRuntimeClass), s_RTCI_ID);			
		}

		// Separate RTCI with anterior comment line
		if(!HasAnteriorComment((ea_t) ptRTCI))
			add_long_cmt((ea_t) ptRTCI, true, "");			

		// Name it
		if(!has_name(Flags) || has_dummy_name(Flags))
		{
			char szStructName[MAXSTR];
			szStructName[0] = szStructName[MAXSTR-1] = 0;
			qsnprintf(szStructName, (MAXSTR-1), "%s_RTCI", szName);
			
			if(!set_name((ea_t) ptRTCI, szStructName, (SN_NON_AUTO | SN_NOWARN)))
			{	
			//msg("%08X \"%s\" SETNAME FAIL.\n", (ea_t) ptRTCI, szStructName);
				// If it fails use the first sequence that works
				for(int i = 0; i < 1000000; i++)
				{				
					//qsnprintf(szStructName, (MAXSTR-1), "%s_RTCI_%d", szName, i);
					//if(set_name((ea_t) ptRTCI, szStructName, (SN_NON_AUTO | SN_NOWARN)))
					//	break;

					char szTempName[MAXSTR];
					qsnprintf(szTempName, (MAXSTR-1), "%s_%d", szStructName, i);
					if(set_name((ea_t) ptRTCI, szTempName, (SN_NON_AUTO | SN_NOWARN)))
						break;
				}
			}
		}

		// Name constructor if it has one
		if(ea_t eaCtor = get_32bit((ea_t) &ptRTCI->m_pfnCreateObject))
		{			
			if(eaCtor != BADADDR)
			{
				flags_t Flags = getFlags(eaCtor);
				if(!has_name(Flags) || has_dummy_name(Flags))
				{
					//Output("%08X CTOR\n", eaCtor);
					char szCtor[MAXSTR];
					szCtor[0] = szCtor[MAXSTR-1] = 0;
					qsnprintf(szCtor, (MAXSTR-1), "??0%s@@QAE@XZ", szName);
					if(!set_name(eaCtor, szCtor, (SN_NON_AUTO | SN_NOWARN)))
					{
					//msg("%08X \"%s\" SETNAME FAIL.\n", (ea_t) eaCtor, szCtor);
						// If it fails use the first sequence that works
						for(int i = 0; i < 1000000; i++)
						{				
							//qsnprintf(szCtor, (MAXSTR-1), "??0%s_%d_@@QAE@XZ", szName, i);
							//if(set_name(eaCtor, szCtor, (SN_NON_AUTO | SN_NOWARN)))
							//	break;

							char szTempName[MAXSTR];
							qsnprintf(szTempName, (MAXSTR-1), "%s_%d", szCtor, i);
							if(set_name(eaCtor, szTempName, (SN_NON_AUTO | SN_NOWARN)))
								break;
						}
					}
				}
			}
		}		

		// Call child recursively
		if(GetVerify32_t((ea_t) &ptRTCI->m_pfnGetBaseClass, ptRTCI))
			DoStruct(ptRTCI);
	}
}

// Get list of base class info
static void GetNextNode(RTCI::CRuntimeClass *ptRTCI, RTCI::BCInfoList &rList)
{
	if(ptRTCI)
	{
		// Get name
		char szName[MAXSTR];
		szName[0] = szName[MAXSTR-1] = 0;
		RTCI::CRuntimeClass::GetName(ptRTCI, szName, SIZESTR(szName));

		// Get object size
		UINT uSize = get_32bit((ea_t) &ptRTCI->m_nObjectSize);

		if(tBCInfo *pNode = new tBCInfo(szName, uSize))
			rList.InsertHead(*pNode);

		// Call child recursively
		if(GetVerify32_t((ea_t) &ptRTCI->m_pfnGetBaseClass, ptRTCI))
			GetNextNode(ptRTCI, rList);	
	}
}
//
void RTCI::GetBCInfo(CRuntimeClass *ptRTCI, BCInfoList &rList)
{
	// Call skip our level
	if(GetVerify32_t((ea_t) &ptRTCI->m_pfnGetBaseClass, ptRTCI))
		GetNextNode(ptRTCI, rList);	
}


// Process RTCI vftable
// Assumes RTCI struct is valid
void RTCI::ProcessVftable(ea_t eaVftable, ea_t eaEnd)
{
	ea_t eaFirstMethod;
	if(GetVerify32_t(eaVftable, eaFirstMethod))
	{
		CRuntimeClass *ptRTCI;
		if(GetVerify32_t(eaFirstMethod+1, ptRTCI))
		{
			// Iterate hierarchy and place structures et al
			CRuntimeClass::DoStruct(ptRTCI);

			// Get name
			char szName[MAXSTR];
			szName[0] = szName[MAXSTR-1] = 0;
			CRuntimeClass::GetName(ptRTCI, szName, SIZESTR(szName));			

			// Set vftable name
			char szNewName[MAXSTR];
			qsnprintf(szNewName, (MAXSTR-1), "??_7%s@@6B@", szName);		
			szNewName[MAXSTR-1] = 0;

			if(has_dummy_name(getFlags(eaVftable)))
			{				
				if(!set_name(eaVftable, szNewName, (SN_NON_AUTO | SN_NOWARN)))
				{	
				//msg("%08X \"%s\" SETNAME FAIL.\n", (ea_t) eaVftable, szNewName);
					// If it fails use the first sequence that works
					for(int i = 0; i < 1000000; i++)
					{						
						//qsnprintf(szNewName, (MAXSTR-1), "??_7%s_%d_@@6B@", szName, i);
						//if(set_name(eaVftable, szNewName, (SN_NON_AUTO | SN_NOWARN)))
						//	break;

						char szTempName[MAXSTR];
						qsnprintf(szTempName, (MAXSTR-1), "%s_%d", szNewName, i);
						if(set_name(eaVftable, szTempName, (SN_NON_AUTO | SN_NOWARN)))
							break;
					}
				}
			}

			// Create simple name
			char szPlainName[MAXSTR];
			GetPlainClassName(szNewName, szPlainName);

			// Set method name
			if(has_dummy_name(getFlags(eaFirstMethod)))
			{
				// Not ideal, should return RTCI* not void*
				char szMethodName[MAXSTR];
				qsnprintf(szMethodName, SIZESTR(szMethodName), "?GetRTCI@%s@@YAPAXXZ", szPlainName); // "?GetRTCI@%s@@YAPAXXZ"
				
				if(!set_name(eaFirstMethod, szMethodName, (SN_NON_AUTO | SN_NOWARN)))
				{
				//msg("%08X \"%s\" SETNAME FAIL.\n", (ea_t) eaFirstMethod, szMethodName);
					// If it fails use the first sequence that works					
					for(int i = 0; i < 1000000; i++)
					{	
						char szTempName2[MAXSTR];
						qsnprintf(szTempName2, (MAXSTR-1), "%s_%d", szMethodName, i);
						if(set_name(eaFirstMethod, szTempName2, (SN_NON_AUTO | SN_NOWARN)))
							break;
					}
				}
			}

			// Build up log and comment string
			BCInfoList tInfoList;
			GetBCInfo(ptRTCI, tInfoList);

			qstring cClassString("");
			cClassString.sprnt("%s", szName);

			if(tBCInfo *pNode = tInfoList.GetTail())
			{				
				cClassString += ':';			

				do
				{
					// Append it
					cClassString.cat_sprnt(" %s,", pNode->m_szName);
					
				}while(pNode = pNode->GetPrev());

				cClassString.remove((cClassString.length() - 1), 1);
				cClassString += "; ";
			}
			else
				cClassString += "; ";

			UINT uSize = get_32bit((ea_t) &ptRTCI->m_nObjectSize);			

			// Log it
			Trace("%s Object size: %d\n", cClassString.c_str(), uSize);
			AddTableEntry(ICON_RTCI, eaVftable, ((eaEnd - eaVftable) / sizeof(UINT)), "%s  Object size: %d", cClassString.c_str(), uSize);

			cClassString.cat_sprnt(" Object size: %d  (Class Informer)", uSize);
				
			if(bOverwriteComents)
			{				
				KillAnteriorComments(eaVftable);				
				add_long_cmt(eaVftable, true, "\nclass %s", cClassString.c_str());
			}
			else
			if(!HasAnteriorComment(eaVftable))
				add_long_cmt(eaVftable, true, "\nclass %s", cClassString.c_str());

			// Process vftable member functions..
			qstrncat(szPlainName, "@@", (MAXSTR-1));
			VFTABLE::ProcessMembers(szPlainName, eaVftable, eaEnd);

			// Clean up list
			while(tBCInfo *pNode = tInfoList.GetHead())
			{
				tInfoList.Remove(*pNode);
				delete pNode;
			};
		}
	}
}