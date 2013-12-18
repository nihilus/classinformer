// ****************************************************************************
// File: RTTI.cpp
// Desc: RTTI defs and support
//
// ****************************************************************************
#include "stdafx.h"
#include "Core.h"
#include "RTTI.h"
#include "Vftable.h"
#include "struct_macros.h"

extern BOOL bDebugOutput;

// Class name list container
struct tBCDInfo : public Container::NodeEx<Container::ListHT, tBCDInfo>
{
	tBCDInfo(LPSTR pszName, UINT uAttribute, UINT mdisp, UINT pdisp, UINT vdisp)
	{ 
		qstrncpy(m_szName, pszName, SIZESTR(m_szName));
        m_szName[SIZESTR(m_szName)] = 0;
				
		// Input must be UINT, trick them back to int
		m_PMD.mdisp = *((PINT) &mdisp);
		m_PMD.pdisp = *((PINT) &pdisp);
		m_PMD.vdisp = *((PINT) &vdisp);

        m_uAttribute = uAttribute;
	}

	static PVOID __cdecl operator new(size_t size) { return(qalloc(size)); };
	static void __cdecl operator delete(PVOID _Ptr){ qfree(_Ptr); }

	char m_szName[MAXSTR];
	RTTI::PMD m_PMD;
	UINT m_uAttribute;
};


namespace RTTI
{
	typedef Container::ListEx<Container::ListHT, tBCDInfo> BCDInfoList;

	void GetBCDInfo(CompleteObjectLocator *pCOL, BCDInfoList &rNameList, UINT &numBaseClasses);
};


// ==== Data ====
static tid_t s_CompleteObjectLocator_ID		= 0;
static tid_t s_type_info_ID					= 0;
static tid_t s_ClassHierarchyDescriptor_ID	= 0;
static tid_t s_PMD_ID						= 0;
static tid_t s_BaseClassDescriptor_ID		= 0;


// Mangle number for labeling
static LPSTR MangleNumber(UINT uNumber, LPSTR pszBuffer)
{
	//
	// 0 = A@
	// X = X-1 (1 <= X <= 10)
	// -X = ? (X - 1)
	// 0x0..0xF = 'A'..'P'	

	// Can only get unsigned inputs
	int iNumber = *((PINT) &uNumber);

	if(iNumber == 0)
		return("A@");
	else
	{
		int sign = 0;
		if(iNumber < 0)
		{
			sign = 1;
			iNumber = -iNumber;
		}

		if(iNumber <= 10)
		{
			qsnprintf(pszBuffer, 16, "%s%d", (sign ? "?" : ""), (iNumber - 1));
			return(pszBuffer);
		}
		else
		{
			// How many digits max?
			char szBuffer2[512] = {0};
			int  iCount = sizeof(szBuffer2);

			while((iNumber > 0) && (iCount > 0))
			{							
				szBuffer2[sizeof(szBuffer2) - iCount] = ('A' + (iNumber % 16));
				iNumber = (iNumber / 16);
				iCount--;
			};

			// ** test
			if(iCount == 0)
				msg(" *** MangleNumber overflow! ***");
			Output("    MN Digits: %d\n", iCount);

			qsnprintf(pszBuffer, 16, "%s%s@", (sign ? "?" : ""), szBuffer2);
			return(pszBuffer);
		}
	}
}

// Return a short label indicating the inheritance type by attributes
static LPCSTR InheritanceLabel(UINT uAttributes)
{
	if((uAttributes & 3) == 1)
		return("[MI]");
	else
	if((uAttributes & 3) == 2)
		return("[VI]");
	else
	if((uAttributes & 3) == 3)
		return("[MI VI]");	

	return("[SI]");
}

// Get icon for inheritance attributes
static int InheritanceIcon(UINT uAttributes)
{
	if((uAttributes & 3) == 1)
		return(ICON_MI);
	else
	if((uAttributes & 3) == 2)
		return(ICON_VI);
	else
	if((uAttributes & 3) == 3)
		return(ICON_MI_VI);	

	return(ICON_SI);
}

// Add RTTI structures to IDA
void RTTI::CreateStructDefs()
{
	// Add RTTI structures to IDA
	struc_t *ptStruct;

	// Member type info for 32bit offset types
	typeinfo_t mtoff = {0};
	mtoff.ri.flags  = REF_OFF32;
	mtoff.ri.target = BADADDR;

	ADD_STRUCT(s_type_info_ID, "type_info", "(Class Informer)");
	if(ptStruct)
	{		
		ADD_MEMBER(ptStruct, offflag()|dwrdflag(), &mtoff, RTTI::type_info, vftable);
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::type_info, _m_data);
		
		// Make name of zero size
		typeinfo_t mt = {0};		
		AddStrucMember(ptStruct, "_m_d_name", offsetof(RTTI::type_info, _m_d_name), asciflag(), &mt, 0);		
	}

	ADD_STRUCT(s_PMD_ID, "PMD", "(Class Informer)");
	if(ptStruct)
	{
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::PMD, mdisp);
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::PMD, pdisp);
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::PMD, vdisp);		
	}

	ADD_STRUCT(s_BaseClassDescriptor_ID, "RTTIBaseClassDescriptor", "(Class Informer)");
	if(ptStruct)
	{	
		ADD_MEMBER(ptStruct, offflag()|dwrdflag(), &mtoff, RTTI::BaseClassDescriptor, pTypeDescriptor);		
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::BaseClassDescriptor, numContainedBases);		
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::BaseClassDescriptor, attributes);

		typeinfo_t mt = {0};
		mt.tid = s_PMD_ID;
		ADD_MEMBER(ptStruct, struflag(), &mt, RTTI::BaseClassDescriptor, pmd);
	}

	ADD_STRUCT(s_ClassHierarchyDescriptor_ID, "RTTIClassHierarchyDescriptor", "(Class Informer)");
	if(ptStruct)
	{
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::ClassHierarchyDescriptor, signature);		
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::ClassHierarchyDescriptor, attributes);
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::ClassHierarchyDescriptor, numBaseClasses);
		ADD_MEMBER(ptStruct, offflag()|dwrdflag(), &mtoff, RTTI::ClassHierarchyDescriptor, pBaseClassArray);
	}

	ADD_STRUCT(s_CompleteObjectLocator_ID, "RTTICompleteObjectLocator", "(Class Informer)");
	if(ptStruct)
	{
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::CompleteObjectLocator, signature);		
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::CompleteObjectLocator, offset);
		ADD_MEMBER(ptStruct, dwrdflag(), NULL, RTTI::CompleteObjectLocator, cdOffset);			
		ADD_MEMBER(ptStruct, offflag()|dwrdflag(), &mtoff, RTTI::CompleteObjectLocator, pTypeDescriptor);
		ADD_MEMBER(ptStruct, offflag()|dwrdflag(), &mtoff, RTTI::CompleteObjectLocator, pClassDescriptor);
	}
}

// Version 1.05, manually set fields and then try "doStruct()"
// If it fails at least the fields should be set
static BOOL doStructEx(ea_t ea, tid_t tid, LPSTR pszName = NULL)
{
	BOOL bResult = FALSE;

	#define PutDword(ea) doDwrd(ea, sizeof(DWORD))

	if(tid == s_type_info_ID)
	{				
		UINT uNameLen    = (strlen(pszName) + 1);
		UINT uStructSize = (offsetof(RTTI::type_info, _m_d_name) + uNameLen);

		// Must mark all structure bytes unknown first
		SetUnknown(ea, uStructSize);
		// Place fields individually first
		PutDword(ea + offsetof(RTTI::type_info, vftable));
		PutDword(ea + offsetof(RTTI::type_info, _m_data));
		doASCI(ea +   offsetof(RTTI::type_info, _m_d_name), uNameLen);     
		// Try to place struct
		doStruct(ea, uStructSize, s_type_info_ID);		
 		
		// The doStruct() return result is unreliable, use the flag instead
		if(isStruct(getFlags(ea)))		
			bResult = TRUE;
		else
		// Version 1.03, fixes a problem with some IDB where there is junk data just prior to
		// a type def.
		{	
			ea_t eaPrev = prev_head(ea, 0);
			if(eaPrev != BADADDR)
			{
				// Make the junk unknown
				SetUnknown(eaPrev, uStructSize + (ea - eaPrev));

				SetUnknown(ea, uStructSize);				
				PutDword(ea + offsetof(RTTI::type_info, vftable));
				PutDword(ea + offsetof(RTTI::type_info, _m_data));
				doASCI(ea +   offsetof(RTTI::type_info, _m_d_name), uNameLen);			 
				doStruct(ea, uStructSize, s_type_info_ID);
			
				if(isStruct(getFlags(ea)))				
				{
					//msg(FMT_EA_X" "FMT_EA_X" FIXED.\n", ea, eaPrev);
					bResult = TRUE;
				}				
			}
		}
	}
	else
	if(tid == s_PMD_ID)
	{
		SetUnknown(ea, sizeof(RTTI::PMD));
		PutDword(ea + offsetof(RTTI::PMD, mdisp));
		PutDword(ea + offsetof(RTTI::PMD, pdisp));
		PutDword(ea + offsetof(RTTI::PMD, vdisp));
		doStruct(ea, sizeof(RTTI::PMD), s_PMD_ID);
		bResult = isStruct(getFlags(ea));
	}
	else
	if(tid == s_BaseClassDescriptor_ID)
	{
		SetUnknown(ea, sizeof(RTTI::BaseClassDescriptor));
		PutDword(ea + offsetof(RTTI::BaseClassDescriptor, pTypeDescriptor));
		PutDword(ea + offsetof(RTTI::BaseClassDescriptor, numContainedBases));
		doStructEx(ea + offsetof(RTTI::BaseClassDescriptor, pmd), s_PMD_ID);
		PutDword(ea + offsetof(RTTI::BaseClassDescriptor, attributes));
	  // ** Missing?
	  PutDword(ea + 4 + offsetof(RTTI::BaseClassDescriptor, attributes));
		doStruct(ea, sizeof(RTTI::BaseClassDescriptor), s_BaseClassDescriptor_ID);
		bResult = isStruct(getFlags(ea));
	}
	else
	if(tid == s_ClassHierarchyDescriptor_ID)
	{
		SetUnknown(ea, sizeof(RTTI::ClassHierarchyDescriptor));
		PutDword(ea + offsetof(RTTI::ClassHierarchyDescriptor, signature));
		PutDword(ea + offsetof(RTTI::ClassHierarchyDescriptor, attributes));
		PutDword(ea + offsetof(RTTI::ClassHierarchyDescriptor, numBaseClasses));
		PutDword(ea + offsetof(RTTI::ClassHierarchyDescriptor, pBaseClassArray));
		doStruct(ea, sizeof(RTTI::ClassHierarchyDescriptor), s_ClassHierarchyDescriptor_ID);
		bResult = isStruct(getFlags(ea));
	}
	else
	if(tid == s_CompleteObjectLocator_ID)
	{
		SetUnknown(ea, sizeof(RTTI::CompleteObjectLocator));
		PutDword(ea + offsetof(RTTI::CompleteObjectLocator, signature));
		PutDword(ea + offsetof(RTTI::CompleteObjectLocator, offset));
		PutDword(ea + offsetof(RTTI::CompleteObjectLocator, cdOffset));
		PutDword(ea + offsetof(RTTI::CompleteObjectLocator, pTypeDescriptor));
		PutDword(ea + offsetof(RTTI::CompleteObjectLocator, pClassDescriptor));
		doStruct(ea, sizeof(RTTI::CompleteObjectLocator), s_CompleteObjectLocator_ID);
		bResult = isStruct(getFlags(ea));
	}
	else
	{
		_ASSERT(FALSE);
		bResult = FALSE;
	}

	return(bResult);
}


// Get type name into a buffer
// type_info assumed to be valid
LPSTR RTTI::type_info::GetName(type_info *pIDA, LPSTR pszBufer, int iSize)
{
	int iLen = get_max_ascii_length((ea_t) &pIDA->_m_d_name, ASCSTR_TERMCHR, true);
	if(iLen > 0)
	{		
		if(iLen > iSize) iLen = iSize;
		if(get_ascii_contents((ea_t) &pIDA->_m_d_name, iLen, ASCSTR_TERMCHR, pszBufer, iSize))		
			return(pszBufer);		
	}	

	return(NULL);
}

// Verify this is a valid type_info type
BOOL RTTI::type_info::IsValid(type_info *pIDA)
{
	if(getFlags((ea_t) &pIDA->vftable))
	{
		// Verify what should be a vftable
		ea_t eaVftable = get_32bit((ea_t) &pIDA->vftable);
		if(eaVftable > 0xFFFFF)
		{		
			// Check type name
			if(getFlags(eaVftable))
			{			
				// Get first 4 bytes of name
				UINT StringBytes = get_32bit((ea_t) &pIDA->_m_d_name);
			
				// Should have type a ".?AVxxxx" name
				return(IsTypeName((LPCSTR) &StringBytes));				
			}
		}
	}

	return(FALSE);
}


// Build struct at address
BOOL RTTI::type_info::DoStruct(type_info *pTypeInfo)
{
	BOOL bResult = FALSE;

	if(bPlaceStructs)
	{
		if(((UINT) pTypeInfo > 0xFFFF) && ((ea_t) pTypeInfo != BADADDR))
		{
			// Get type name
			char szName[MAXSTR]; szName[0] = szName[SIZESTR(szName)] = 0;
			GetName(pTypeInfo, szName, (MAXSTR - 1));
									
			bResult = doStructEx((ea_t) pTypeInfo, s_type_info_ID, szName);						
		
			// Can't name it if structure place failed
			//if(bResult)
			{
				flags_t Flags = getFlags((ea_t) pTypeInfo);
				if(!has_name(Flags) || has_dummy_name(Flags))
				{
					// Set name/label
					char szName2[MAXSTR]; szName2[SIZESTR(szName2)] = 0;
					qsnprintf(szName2, (MAXSTR-1), "??_R0?%s@8", szName+2);
					
					if(!set_name((ea_t) pTypeInfo, szName2, (SN_NON_AUTO | SN_NOWARN | SN_NOCHECK)))
					{					
						/* 
							Version 1.03
							Even when this "set_name()" fails, it appears the name is set anhow, prehaps
							set by the system.
							On top of that, the code below would set the wrong suffix name anyhow.
							It needs to be added after the first '@' char

							The fail see seen from trying to label an invalid type structure anyhow.
						*/				

						#if 0
						// If it fails use the first sequence that works					
						for(int i = 0; i < 1000000; i++)
						{
							qsnprintf(szBuffer2, (MAXSTR-1), "??_R0?%s_%d@8", szBuffer1+2, i);               
							if(set_name((ea_t) pTypeInfo, szBuffer2, (SN_NON_AUTO | SN_NOWARN | SN_NOCHECK)))
								break;
						}
						#endif
					}
				}
			}
			//else			
			//	msg(" "FMT_EA_X" *** type_info::DoStruct() failed! ***\n", pTypeInfo);							
		}		
	}

	return(bResult);
}

// Return TRUE if address is a valid RTTI structure
BOOL RTTI::CompleteObjectLocator::IsValid(CompleteObjectLocator *pCOL)
{
	if((ea_t) pCOL != BADADDR)
	{
		if((ea_t) pCOL > 0xFFFF)
		{
			if(getFlags((ea_t) &pCOL->signature))
			{
				CompleteObjectLocator tCOL;
				if(GetVerify32_t((ea_t) &pCOL->signature, tCOL.signature))
				{		
					//if(GetVerify32_t((ea_t) &pCOL->offset, tCOL.offset))
					{
						//if(GetVerify32_t((ea_t) &pCOL->cdOffset, tCOL.cdOffset))
						{
							// Pointer to type_info
							if(GetVerify32_t((ea_t) &pCOL->pTypeDescriptor, tCOL.pTypeDescriptor))
							{
								// Must have valid "type_info"
								if((UINT) tCOL.pTypeDescriptor > 0xFFFF)
								{																						
									if(RTTI::type_info::IsValid(tCOL.pTypeDescriptor))
									{
										if(GetVerify32_t((ea_t) &pCOL->pClassDescriptor, tCOL.pClassDescriptor))
										{												
											return(TRUE);
										}									
									}
								}
							}
						}
					}			
				}
			}
		}
	}

	return(FALSE);
}

// Do RTTI structure at address
BOOL RTTI::BaseClassDescriptor::DoStruct(BaseClassDescriptor *pBCD, OUT LPSTR pszBaseClassName)
{	
	if(((UINT) pBCD > 0xFFFF) && ((ea_t) pBCD != BADADDR))
	{
		flags_t Flags = getFlags((ea_t) pBCD);
		if(bPlaceStructs)		
			doStructEx((ea_t) pBCD, s_BaseClassDescriptor_ID);		

		// Place type_info struct
		type_info *pTypeInfo = (type_info *) get_32bit((ea_t) &pBCD->pTypeDescriptor);
		type_info::DoStruct(pTypeInfo);


		// Get raw type/class name
		char szBuffer1[MAXSTR] = {0};		
		type_info::GetName(pTypeInfo, szBuffer1, (MAXSTR - 1));

		// String with out prefix
		qstrncpy(pszBaseClassName, szBuffer1+SIZESTR(".?Ax"), (MAXSTR - (4+1)));
		pszBaseClassName[MAXSTR-1] = 0;

		if(!has_name(Flags) || has_dummy_name(Flags))
		{
			// Give it a label		
			// Name::`RTTI Base Class Descriptor at (0, -1, 0, 0)'		
			memset(szBuffer1, 0, sizeof(szBuffer1));

			char szBuff2[512] = {0}, szBuff3[512] = {0}, szBuff4[512] = {0}, szBuff5[512] = {0};
			qsnprintf(szBuffer1, (MAXSTR-1), "??_R1%s%s%s%s%s8", 
			MangleNumber(get_32bit((ea_t) &pBCD->pmd.mdisp), szBuff2),
			MangleNumber(get_32bit((ea_t) &pBCD->pmd.pdisp), szBuff3),
			MangleNumber(get_32bit((ea_t) &pBCD->pmd.vdisp), szBuff4), 
			MangleNumber(get_32bit((ea_t) &pBCD->attributes), szBuff5),
					  pszBaseClassName);
			
			if(!set_name((ea_t) pBCD, szBuffer1, (SN_NON_AUTO | SN_NOWARN)))
			{
			//msg(FMT_EA_X" \"%s\" SETNAME FAIL.\n", (ea_t) pBCD, szBuffer1);
				// If it fails use the first sequence that works					
				for(int i = 0; i < 1000000; i++)
				{	
					char szTempName[MAXSTR];
					qsnprintf(szTempName, (MAXSTR-1), "%s_%d", szBuffer1, i);
					if(set_name((ea_t) pBCD, szTempName, (SN_NON_AUTO | SN_NOWARN)))
						break;
				}
			}
		}
	
		return(TRUE);
	}

	memcpy(pszBaseClassName, "Unknown", sizeof("Unknown"));
	return(FALSE);
}


// Do RTTI structure at address
BOOL RTTI::ClassHierarchyDescriptor::DoStruct(ClassHierarchyDescriptor *pCHD)
{
	if(((UINT) pCHD > 0xFFFF) && ((ea_t) pCHD != BADADDR))
	{		
		flags_t Flags = getFlags((ea_t) pCHD);
		
		// Place CHD
		if(bPlaceStructs)
			doStructEx((ea_t) pCHD, s_ClassHierarchyDescriptor_ID);		

		// Place BCD's
		UINT numBaseClasses = 0;
		if(GetVerify32_t((ea_t) &pCHD->numBaseClasses, numBaseClasses))
		{			
			// Get PCA pointer
			ea_t eaBaseClassArray = get_32bit((ea_t) &pCHD->pBaseClassArray);
			if(eaBaseClassArray && (eaBaseClassArray != BADADDR))
			{
				// Create offset string based on input digits
				char szFormat[32];
				int iDigits = strlen(_itoa(numBaseClasses, szFormat, 10));
				if(iDigits > 1)
					qsnprintf(szFormat, SIZESTR(szFormat), "  BaseClass[%%0%dd]", iDigits);
				else
					qstrncpy(szFormat, "  BaseClass[%d]", SIZESTR(szFormat));					
				
				for(UINT i = 0; i < numBaseClasses; i++, eaBaseClassArray += 4)
				{
					// Force it 32bit value								
					FixDWORD(eaBaseClassArray);

					// Add index comment to to it
					if(numBaseClasses == 1)
					{						
						set_cmt(eaBaseClassArray, "  BaseClass", false);
					}
					else
					{
						char szPtrCmt[MAXSTR];
						qsnprintf(szPtrCmt, (MAXSTR-1), szFormat, i);
						szPtrCmt[MAXSTR-1] = 0;
				
						set_cmt(eaBaseClassArray, szPtrCmt, false);
					}

					// Please BCD struct, and grab the base class name
					char szBaseName[MAXSTR];																
					BaseClassDescriptor::DoStruct((BaseClassDescriptor *) get_32bit(eaBaseClassArray), szBaseName);
					
					// Now we have the base class name, name and label some things
					if(i == 0)
					{														
						// Set array name
						flags_t Flags2 = getFlags(eaBaseClassArray);
						if(!has_name(Flags2) || has_dummy_name(Flags2))
						{						
							// ??_R2A@@8 = A::`RTTI Base Class Array'
							char szMangledName[MAXSTR];
							szMangledName[0] = szMangledName[MAXSTR-1] = 0;
							qsnprintf(szMangledName, (MAXSTR-1), "??_R2%s8", szBaseName);														
							if(!set_name(eaBaseClassArray, szMangledName, (SN_NON_AUTO | SN_NOWARN)))
							{
							//msg(FMT_EA_X" \"%s\" SETNAME FAIL.\n", (ea_t) eaBaseClassArray, szMangledName);
								// If it fails use the first sequence that works					
								for(int i = 0; i < 1000000; i++)
								{	
									char szTempName[MAXSTR];
									qsnprintf(szTempName, (MAXSTR-1), "%s_%d", szMangledName, i);
									if(set_name(eaBaseClassArray, szTempName, (SN_NON_AUTO | SN_NOWARN)))
										break;
								}
							}
						}

						// Add a spacing anterior comment line						
						if(bOverwriteComents)
						{
							KillAnteriorComments(eaBaseClassArray);							
							add_long_cmt(eaBaseClassArray, true, "");
						}
						else
						if(!HasAnteriorComment(eaBaseClassArray))
							add_long_cmt(eaBaseClassArray, true, "");

						// Set CHD name
						if(!has_name(Flags) || has_dummy_name(Flags))
						{
							// ??_R3A@@8 = A::`RTTI Class Hierarchy Descriptor'
							char szMangledName[MAXSTR];
							szMangledName[0] = szMangledName[MAXSTR-1] = 0;
							qsnprintf(szMangledName, (MAXSTR-1), "??_R3%s8", szBaseName);							
							
							if(!set_name((ea_t) pCHD, szMangledName, (SN_NON_AUTO | SN_NOWARN)))
							{
							//msg(FMT_EA_X" \"%s\" SETNAME FAIL.\n", (ea_t) pCHD, szMangledName);
								// If it fails use the first sequence that works					
								for(int i = 0; i < 1000000; i++)
								{	
									char szTempName[MAXSTR];
									qsnprintf(szTempName, (MAXSTR-1), "%s_%d", szMangledName, i);
									if(set_name((ea_t) pCHD, szTempName, (SN_NON_AUTO | SN_NOWARN)))
										break;
								}
							}
						}
					}	
				}

				// Make following DWORD if it's bytes are zeros
				if(numBaseClasses > 0)
				{
					if(getFlags(eaBaseClassArray))
					{
						if(get_32bit(eaBaseClassArray) == 0)
							FixDWORD(eaBaseClassArray);
					}
				}
			}			
		}

		return(TRUE);
	}

	return(FALSE);
}


// Do RTTI structure hierarchy at address
// ** Address assumed to be at a valid RTTI COL
BOOL RTTI::CompleteObjectLocator::DoStruct(CompleteObjectLocator *pCOL)
{
	if(((UINT) pCOL > 0xFFFF) && ((ea_t) pCOL != BADADDR))
	{			
		if(bPlaceStructs)	
			doStructEx((ea_t) pCOL, s_CompleteObjectLocator_ID);		

		// Place type_info struct
		type_info *pTypeInfo = (type_info *) get_32bit((ea_t) &pCOL->pTypeDescriptor);
		type_info::DoStruct(pTypeInfo);	

		// Place CHD hierarchy
		ClassHierarchyDescriptor::DoStruct((ClassHierarchyDescriptor *) get_32bit((ea_t) &pCOL->pClassDescriptor));	

		return(TRUE);
	}

	return(FALSE);
}

// Get list of base class names
void RTTI::GetBCDInfo(CompleteObjectLocator *pCOL, BCDInfoList &rtNameList, UINT &numBaseClasses)
{
	numBaseClasses = 0;

	if(ClassHierarchyDescriptor *pCHD = (ClassHierarchyDescriptor *) get_32bit((ea_t) &pCOL->pClassDescriptor))
	{
		if(numBaseClasses = get_32bit((ea_t) &pCHD->numBaseClasses))
		{
			// Get PCA pointer
			ea_t eaBaseClassArray = get_32bit((ea_t) &pCHD->pBaseClassArray);
			if(eaBaseClassArray && (eaBaseClassArray != BADADDR))
			{
				for(UINT i = 0; i < numBaseClasses; i++, eaBaseClassArray += 4)
				{
					// Get next BCD
					BaseClassDescriptor *pBCD = (BaseClassDescriptor *) get_32bit(eaBaseClassArray);
					
					// Get it's raw type name
					// .?AVName@@
					type_info *pTypeInfo = (type_info *) get_32bit((ea_t) &pBCD->pTypeDescriptor);
					char szBuffer1[MAXSTR] = {0};
					type_info::GetName(pTypeInfo, szBuffer1, (MAXSTR - 1));					

					// Add info to list
					UINT mdisp = get_32bit((ea_t) &pBCD->pmd.mdisp);
					UINT pdisp = get_32bit((ea_t) &pBCD->pmd.pdisp);
					UINT vdisp = get_32bit((ea_t) &pBCD->pmd.vdisp);
					UINT attributes = get_32bit((ea_t) &pBCD->attributes);		
					
					if(tBCDInfo *pNode = new tBCDInfo(szBuffer1, attributes, mdisp, pdisp, vdisp))
						rtNameList.InsertHead(*pNode);

					Output("   BN: [%d] \"%s\", ATB: %04X\n", i, szBuffer1, get_32bit((ea_t) &pBCD->attributes));																
					Output("       mdisp: %d, pdisp: %d, vdisp: %d, attributes: %04X\n", *((PINT) &mdisp), *((PINT) &pdisp), *((PINT) &vdisp), attributes);					
				}
			}
		}
	}
}


// Process RTTI vftable info
// Assumed to be valid
void RTTI::ProcessVftable(ea_t eaVftable, ea_t eaEnd)
{
	// Get the COL for this vftable
	CompleteObjectLocator *pCOL = (CompleteObjectLocator *) get_32bit(eaVftable - 4);

	// Get raw type/class name in COL
	// .?AVName@@
	type_info *pTypeInfo = (type_info *) get_32bit((ea_t) &pCOL->pTypeDescriptor);
	char szRawTypeName[MAXSTR];
	type_info::GetName(pTypeInfo, szRawTypeName, (MAXSTR - 1));
	szRawTypeName[MAXSTR-1] = 0;	
	Output("  RTN: \"%s\"\n", szRawTypeName);

	// Iterate RTTI and place structures et al	
	FixDWORD(eaVftable - 4);	
	CompleteObjectLocator::DoStruct(pCOL);	

	// This COL's offset
	UINT COL_Offset = get_32bit((ea_t) &pCOL->offset);

	// Get CHD 'attributes'
	ClassHierarchyDescriptor *pCHD = (ClassHierarchyDescriptor *) get_32bit((ea_t) &pCOL->pClassDescriptor);
	UINT CHD_Attributes = get_32bit((ea_t) &pCHD->attributes);	

	// Get a list of base class info
	BCDInfoList tBCDInfoList;
	UINT numBaseClasses = 0;
	GetBCDInfo(pCOL, tBCDInfoList, numBaseClasses);

	// Single inheritance hierarchy
	if((COL_Offset == 0) && ((CHD_Attributes & (CHDF_MULTIPLE | CHDF_VIRTUAL)) == 0))
	{
		// Decorate raw name as a vftable
		//  const Name::`vftable'
		char szNewName[MAXSTR];
		qsnprintf(szNewName, (MAXSTR-1), "??_7%s6B@", szRawTypeName+SIZESTR(".?Ax"));		
		szNewName[MAXSTR-1] = 0;	

		// Clean up name to a simple form
		// Get nice name by demangling
		// 'Name', 'A::Name', etc.
		char szPlainName[MAXSTR];
		GetPlainClassName(szNewName, szPlainName);		
		Output("    NM: \"%s\", PN: \"%s\"\n", szNewName, szPlainName);		
	
		// Set the vftable name, if it's not named already
		if(has_dummy_name(getFlags(eaVftable)))
		{			
			if(!set_name(eaVftable, szNewName, (SN_NON_AUTO | SN_NOWARN)))
			{
			//msg(FMT_EA_X" \"%s\" SETNAME FAIL.\n", (ea_t) eaVftable, szNewName);
				//msg(" "FMT_EA_X" ** Vftable name set failed, a duplicate? 1: \"%s\",  \"%s\" **\n", eaVftable, szNewName, szPlainName);

				// If it fails use the first sequence that works					
				for(int i = 0; i < 1000000; i++)
				{	
					char szTempName[MAXSTR];
					qsnprintf(szTempName, (MAXSTR-1), "%s_%d", szNewName, i);
					if(set_name(eaVftable, szTempName, (SN_NON_AUTO | SN_NOWARN)))
						break;
				}
			}
		}	

		// Build decorated RTTI COL name
		// const Name::`RTTI Complete Object Locator'
		qsnprintf(szNewName, (MAXSTR-1), "??_R4%s6B@", szRawTypeName+SIZESTR(".?Ax")); szNewName[MAXSTR-1] = 0;		
		if(!set_name((ea_t) pCOL, szNewName, (SN_NON_AUTO | SN_NOWARN)))
		{
		//msg(FMT_EA_X" \"%s\" SETNAME FAIL.\n", (ea_t) pCOL, szNewName);
			// If it fails use the first sequence that works					
			for(int i = 0; i < 1000000; i++)
			{	
				char szTempName[MAXSTR];
				qsnprintf(szTempName, (MAXSTR-1), "%s_%d", szNewName, i);
				if(set_name((ea_t) pCOL, szTempName, (SN_NON_AUTO | SN_NOWARN)))
					break;
			}
		}

		// Build class hierarchy string
		{
			qstring cCmtString(szPlainName);			
			
			// Process BCD list
			if(numBaseClasses > 1)
			{
				cCmtString += ": ";

				// Concat class hierarchy				
				tBCDInfo *pNode = tBCDInfoList.GetTail();
				while(pNode = pNode->GetPrev())
				{				
					// Make a clean class/struct name
					qsnprintf(szNewName, (MAXSTR-1), "??_7%s6B@", pNode->m_szName+SIZESTR(".?Ax"));
					szNewName[MAXSTR-1] = 0;
					GetPlainClassName(szNewName, szPlainName);

					// Append it
					cCmtString.cat_sprnt("%s%s, ", ((pNode->m_szName[3] == 'V') ? "" : "struct "), szPlainName);				
				};
		
				// Nix the ending ','
				cCmtString.remove((cCmtString.length() - 2), 2);
			}
			cCmtString += ';';

			// Log it
			if(bDebugOutput) Trace("%s%s  %s\n", ((szRawTypeName[3] == 'V') ? "" : "struct "), cCmtString.c_str(), InheritanceLabel(CHD_Attributes));
			AddTableEntry(InheritanceIcon(CHD_Attributes), eaVftable, ((eaEnd - eaVftable) / sizeof(UINT)), "%s%s  %s", ((szRawTypeName[3] == 'V') ? "" : "struct "), cCmtString.c_str(), InheritanceLabel(CHD_Attributes));

			// End of comment
			cCmtString.cat_sprnt("  %s O: %d, A: %d  (Class Informer)", InheritanceLabel(CHD_Attributes), COL_Offset, CHD_Attributes);

			// Add a separating anterior comment above RTTI COL						
			ea_t eaComment = (eaVftable-4);
			if(bOverwriteComents)
			{				
				KillAnteriorComments(eaComment);					
				add_long_cmt(eaComment, true, "\n%s %s", ((szRawTypeName[3] == 'V') ? "class" : "struct"), cCmtString.c_str());
			}
			else
			if(!HasAnteriorComment(eaComment))
				add_long_cmt(eaComment, true, "\n%s %s", ((szRawTypeName[3] == 'V') ? "class" : "struct"), cCmtString.c_str());

			// Process vftable member functions..
			VFTABLE::ProcessMembers(szPlainName, eaVftable, eaEnd);
		}
	}
	// Multiple inheritance, and, or, virtual inheritance hierarchies
	else
	{
		tBCDInfo *pMyNode = NULL;
		if(numBaseClasses > 0)
		{	
			// Get our name by matching our offset to the first matching BCD displacement
			if(tBCDInfo *pNode = tBCDInfoList.GetTail())
			{
				do
				{					
					// Match?
					if(pNode->m_PMD.mdisp == COL_Offset)
					{
						pMyNode = pNode;
						break;
					}
					
				} while(pNode = pNode->GetPrev());
			}					

			// If not found, use the first base class instead
			if(pMyNode == NULL)
			{
				//msg(FMT_EA_X" ** RTTI: MI/VI hierarchy level not found, using first base **\n", eaVftable);

				if(tBCDInfo *pNode = tBCDInfoList.GetTail())
				{				
					do 
					{
						// Match?
						if(pNode->m_PMD.pdisp != -1)
						{
							pMyNode = pNode;
							break;
						}
						
					} while(pNode = pNode->GetPrev());				
				}
			}
		}

		// Found our location in the tree..
		if(pMyNode)
		{
			// Combine COL name, and the CHD one						
			char szNewName[MAXSTR];
			qsnprintf(szNewName, (MAXSTR-1), "%s6B%s@", szRawTypeName+SIZESTR(".?Ax"), pMyNode->m_szName+SIZESTR(".?Ax"));		
			szNewName[MAXSTR-1] = 0;
			
			// Vftable name
			char szTempName[MAXSTR];
			qstrncat(qstrncpy(szTempName, "??_7", sizeof("??_7")), szNewName, (MAXSTR-(1+SIZESTR("??_7"))));

			// Simple format
			char szPlainName[MAXSTR];
			GetPlainClassName(szTempName, szPlainName);		
			Output("    NM: \"%s\", PN: \"%s\"\n", szTempName, szPlainName);		

			// Set the vftable name, if it's not named already
			if(has_dummy_name(getFlags(eaVftable)))
			{							
				if(!set_name(eaVftable, szTempName, (SN_NON_AUTO | SN_NOWARN)))
				{
				//msg(FMT_EA_X" \"%s\" SETNAME FAIL.\n", (ea_t) eaVftable, szTempName);
					//msg(" "FMT_EA_X" ** Vftable name set failed, a duplicate? 2: \"%s\",  \"%s\" **\n", eaVftable, szTempName, szPlainName);

					// If it fails use the first sequence that works					
					for(int i = 0; i < 1000000; i++)
					{	
						char szTempName2[MAXSTR];
						qsnprintf(szTempName2, (MAXSTR-1), "%s_%d", szTempName, i);
						if(set_name(eaVftable, szTempName2, (SN_NON_AUTO | SN_NOWARN)))
							break;
					}
				}
			}

			// Proper COL name			
			qstrncat(qstrncpy(szTempName, "??_R4", sizeof("??_R4")), szNewName, (MAXSTR-(1+SIZESTR("??_R4"))));
			if(!set_name((ea_t) pCOL, szTempName, (SN_NON_AUTO | SN_NOWARN)))
			{
				// If it fails use the first sequence that works					
				for(int i = 0; i < 1000000; i++)
				{	
					char szTempName2[MAXSTR];
					qsnprintf(szTempName2, (MAXSTR-1), "%s_%d", szTempName, i);
					if(set_name((ea_t) pCOL, szTempName2, (SN_NON_AUTO | SN_NOWARN)))
						break;
				}
			}
			
			// Build class hierarchy string			
			qstring cCmtString(szPlainName);			

			// Concat classes to the right of us						
			if(tBCDInfo *pNode = pMyNode->GetPrev())
			{
				cCmtString += ": ";

				do
				{
				    // Make plain name
					qsnprintf(szNewName, (MAXSTR-1), "??_7%s6B@", pNode->m_szName+SIZESTR(".?Ax"));
					szNewName[MAXSTR-1] = 0;
					GetPlainClassName(szNewName, szPlainName);

					// Append it
					cCmtString.cat_sprnt("%s%s, ", ((pNode->m_szName[3] == 'V') ? "" : "struct "), szPlainName);										

				}while(pNode = pNode->GetPrev());
				
				cCmtString.remove((cCmtString.length() - 2), 2);
			}
			
			/*
			// To the right if there is any
			if(tBCDInfo *pNode = pMyNode->GetNext())
			{
				cCmtString += " (after ";

				while(pNode)
				{			
					// Make plain name
					qsnprintf(szNewName, (MAXSTR-1), "??_7%s6B@", pNode->m_szName+SIZESTR(".?Ax"));
					szNewName[MAXSTR-1] = 0;
					GetPlainClassName(szNewName, szPlainName);

					// Append it
					cCmtString.cat_sprnt("%s%s, ", ((pNode->m_szName[3] == 'V') ? "" : "struct "), szPlainName);

					pNode = pNode->GetNext();	
				};

				cCmtString.remove((cCmtString.length() - 2), 2);
				cCmtString += ")";
			}
			*/
			cCmtString += ';';
			
			// Log it
			if(bDebugOutput) Trace("%s%s  %s\n", ((pMyNode->m_szName[3] == 'V') ? "" : "struct "), cCmtString.c_str(), InheritanceLabel(CHD_Attributes));
			AddTableEntry(InheritanceIcon(CHD_Attributes), eaVftable, ((eaEnd - eaVftable) / sizeof(UINT)), "%s%s  %s", ((pMyNode->m_szName[3] == 'V') ? "" : "struct "), cCmtString.c_str(), InheritanceLabel(CHD_Attributes));

			// End of comment
			cCmtString.cat_sprnt("  %s O: %d, A: %d  (Class Informer)", InheritanceLabel(CHD_Attributes), COL_Offset, CHD_Attributes);

			// Add a separating anterior comment above RTTI COL													
			ea_t eaComment = (eaVftable-4);
			if(bOverwriteComents)
			{				
				KillAnteriorComments(eaComment);					
				add_long_cmt(eaComment, true, "\n%s %s", ((pMyNode->m_szName[3] == 'V') ? "class" : "struct"), cCmtString.c_str());
			}
			else
			if(!HasAnteriorComment(eaComment))
				add_long_cmt(eaComment, true, "\n%s %s", ((pMyNode->m_szName[3] == 'V') ? "class" : "struct"), cCmtString.c_str());

			VFTABLE::ProcessMembers(szPlainName, eaVftable, eaEnd);
		}


		// Couldn't get name, use just use COL type name
		if(pMyNode == NULL)
		{
			msg(FMT_EA_X" ** RTTI: Multiple or virtual inheritance level not found, using COL def name **\n", eaVftable);
			
			type_info *pTypeInfo = (type_info *) get_32bit((ea_t) &pCOL->pTypeDescriptor);
			char szTopTypeNameRaw[MAXSTR];
			type_info::GetName(pTypeInfo, szTopTypeNameRaw, (MAXSTR - 1));
			szTopTypeNameRaw[MAXSTR-1] = 0;	
			Output("  RTN: \"%s\"\n", szTopTypeNameRaw);
			
			char szNewName[MAXSTR];
			qsnprintf(szNewName, (MAXSTR-1), "??_7%s6B@", szTopTypeNameRaw+SIZESTR(".?Ax"));		
			szNewName[MAXSTR-1] = 0;

			char szPlainName[MAXSTR];
			GetPlainClassName(szNewName, szPlainName);		
			Output("    NM: \"%s\", PN: \"%s\"\n", szNewName, szPlainName);
			
			// Set the vftable name, if it's not named already
			if(has_dummy_name(getFlags(eaVftable)))
			{				
				if(!set_name(eaVftable, szNewName, (SN_NON_AUTO | SN_NOWARN)))
				{
				//msg(FMT_EA_X" \"%s\" SETNAME FAIL.\n", (ea_t) eaVftable, szNewName);
					//msg(" "FMT_EA_X" ** Vftable name set failed, a duplicate? 3: \"%s\",  \"%s\" **\n", eaVftable, szNewName, szPlainName);

					// If it fails use the first sequence that works					
					for(int i = 0; i < 1000000; i++)
					{	
						char szTempName[MAXSTR];
						qsnprintf(szTempName, (MAXSTR-1), "%s_%d", szNewName, i);
						if(set_name(eaVftable, szTempName, (SN_NON_AUTO | SN_NOWARN)))
							break;
					}
				}
			}							

			qstring cCmtString(szPlainName);			

			// Log it
			if(bDebugOutput) Trace("%s%s  (** problem **) %s\n", ((szRawTypeName[3] == 'V') ? "" : "struct "), cCmtString.c_str(), InheritanceLabel(CHD_Attributes));
			AddTableEntry(InheritanceIcon(CHD_Attributes), eaVftable, ((eaEnd - eaVftable) / sizeof(UINT)), "%s%s  (** problem **) %s", ((szRawTypeName[3] == 'V') ? "" : "struct "), cCmtString.c_str(), InheritanceLabel(CHD_Attributes));
			cCmtString.cat_sprnt("  %s (** problem **) O: %d, A: %d  (Class Informer)", InheritanceLabel(CHD_Attributes), COL_Offset, CHD_Attributes);
									
			ea_t eaComment = (eaVftable-4);
			if(bOverwriteComents)
			{				
				KillAnteriorComments(eaComment);					
				add_long_cmt(eaComment, true, "\n%s %s", ((szRawTypeName[3] == 'V') ? "class" : "struct"), cCmtString.c_str());
			}
			else
			if(!HasAnteriorComment(eaComment))
				add_long_cmt(eaComment, true, "\n%s %s", ((szRawTypeName[3] == 'V') ? "class" : "struct"), cCmtString.c_str());

			VFTABLE::ProcessMembers(szPlainName, eaVftable, eaEnd);
		}
	}

	// Clean up BCD list
	while(tBCDInfo *pNode = tBCDInfoList.GetHead())
	{
		tBCDInfoList.Remove(*pNode);
		delete pNode;
	};
}