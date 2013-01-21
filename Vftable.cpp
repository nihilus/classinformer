
// ****************************************************************************
// File: Vftable.cpp 
// Desc: Vftable support
//
// ****************************************************************************
#include "stdafx.h"
#include "Core.h"
#include "Vftable.h"
#include "RTTI.h"

namespace VFTABLE
{
	int TryKnownMember(LPCTSTR lpszName, ea_t eaMember);
};

// Return TRUE, along with some vftable info if there is one at address
BOOL VFTABLE::GetTableInfo(ea_t eaAddress, tINFO &rtInfo)
{
	//Output(" Checking for vftable at: %08X\n", eaAddress);

	// Start of vftable should have a xref and a name (auto or manual)	
	flags_t Flags = getFlags(eaAddress);  
	if(!(hasRef(Flags) || has_any_name(Flags) && (isDwrd(Flags) || isUnknown(Flags))))
	{
		//Output(" Start of vftable should have a xref and a name (auto or manual)\n");
		//Output(" Flags: %02X\n");
		return(FALSE);
	}
	else
	// Continue..
	{
		// Should have a xref too us..
		BOOL bHasAMoveXref = FALSE;
		ea_t eaCodeRef = get_first_dref_to(eaAddress);
		if(eaCodeRef && (eaCodeRef != BADADDR))
		{
			//Output(" \n");
			//Output("%08X has xref(s) to code.\n", eaAddress);

			do 
			{
				//Output("    %08X\n", eaCodeRef);

				// Will be code		
				if(isCode(getFlags(eaCodeRef)))
				{
					// OOP_RE: Check the code to for "mov" instructions to verify
					// Must be a "mov" w/"offset" instruction
					LPCTSTR pszLine = GetDisasmText(eaCodeRef);
					if((*((PUINT) pszLine) == 0x20766F6D /*"mov "*/) && (strstr(pszLine+4, " offset ") != NULL))
					{
						//Output("    %08X %08X OK \"%s\"\n", eaCodeRef, getFlags(eaCodeRef), pszLine);
						bHasAMoveXref = TRUE;
						break;
					}
					//else
					//	Output("    %08X %08X NOT \"%s\"\n", eaCodeRef, getFlags(eaCodeRef), pszLine);
				}			
				else			
				// Else maybe problem a problem case, double check for a "mov" opcode
				if(get_original_byte(eaCodeRef) == 0xC7 /*mov [xx], offset*/)
				{
					msg(" %08X ** Found alternate \"mov\" opcode here **\n", eaCodeRef);
				}	
				
				eaCodeRef = get_next_dref_to(eaAddress, eaCodeRef);

			}while(eaCodeRef && (eaCodeRef != BADADDR));		
		}
		if(!bHasAMoveXref)
		{
			//Output(" %08X ** No code ref has 'mov' instruction **\n");
			return(FALSE);
		}

		// Default clear info struct
		ZeroMemory(&rtInfo, sizeof(tINFO));

		// Get it's raw (auto-generated mangled, or user named) name
		// Typically "unk_xxxxxxxx"
		if(get_name(BADADDR, eaAddress, rtInfo.szName, (MAXSTR - 1)))
		{						
			//Output(" Raw name: \"%s\".\n", rtInfo.szName);
		}
		else
			msg(" %08X *** GetVftableInfo(): Failed to get raw name! ***\n", eaAddress);
		

		//== Walk the table down to get it's size
		ea_t eaStart = rtInfo.eaStart = eaAddress;
		while(TRUE)
		{
			// Should be DWORD offset to a function here (could be unknown if dirty IDB)
			flags_t IndexFlags = getFlags(eaAddress);
			//Output(" %08X -M- hasValue:%d, isData:%d, isOff0:%d, isDwrd:%d, isUnknown: %d\n", eaAddress, hasValue(IndexFlags), isData(IndexFlags), isOff0(IndexFlags), isDwrd(IndexFlags), isUnknown(IndexFlags));     
			//if(!(hasValue(IndexFlags) && isData(IndexFlags) && isOff0(IndexFlags) /*&& isDwrd(IndexFlags)*/))
			if(!(hasValue(IndexFlags) && (isDwrd(IndexFlags) || isUnknown(IndexFlags))))
			{
				//Output(" ******* 1\n");
				break;
			}

			//= Look at what this (assumed vtable) index points too
			ea_t eaIndexValue = get_32bit(eaAddress);
			if(!(eaIndexValue && (eaIndexValue != BADADDR)))
			{
				//Output(" ******* 2\n");
				break;
			}

			// Shouldn't see a ref after first index, if so probably the beginning of the next one
			if(eaAddress != eaStart)
			{
				if(hasRef(IndexFlags))
				{
					//Output(" ******* 3\n");
					break;
				}

				// If value is a valid RTTI CompleteObjectLocator it probably belongs to the next
				if(RTTI::CompleteObjectLocator::IsValid((RTTI::CompleteObjectLocator *) eaIndexValue))
					break;
			}

			// *** Jan 2010, a lot looser checks now
			// Yes most of the time it should be a function here, but it could be just a code block, or just a "missing function".
			// Assume if the ref is just code, then it's all right.		
			flags_t ValueFlags = getFlags(eaIndexValue);
			//Output("   %08X -R- hasValue: %d, isCode: %d, isFunc: %d, *%08X\n", eaIndexValue, hasValue(ValueFlags), isCode(ValueFlags), isFunc(ValueFlags), get_32bit(eaIndexValue));
			if(!isCode(ValueFlags))
			{
				//Output(" ******* 4\n");
				break;
			}
			else
			// Another fix for dirty IDB, if it's undefined we'll make it a DWORD
			// Which might cause yet another chain reaction and fix more missing stuff		
			if(isUnknown(IndexFlags))
			{	
				// Fix member pointer and possibly fix and find more refs, etc.							
				FixDWORD(eaAddress);				
			}

			// And since we are expecting a function pointer, see if we can do yet more clean up			
			if(add_func(eaIndexValue, BADADDR))
			{				
				// ** To much spam for large dirty IDBs
				//msg("  %08X Fixed missing member function.\n", eaIndexValue);
			}

		
			#if 0
			// Note: Not 100% accurate since the index could point to code, but not dissembled correctly					
			// Value should be code and a function start
			Output("   %08X hasValue: %d, isCode: %d, isFunc: %d, * %08X\n", eaIndexValue, hasValue(Flags), isCode(Flags), isFunc(Flags), get_32bit(eaIndexValue));
			if(!isFunc(Flags))
			{
				Output(" ******* 4\n");
				break;	
			}
			#endif
		
			eaAddress += sizeof(UINT);
		};
			
		if((rtInfo.uMethods = ((eaAddress - eaStart) / sizeof(UINT))) > 0)
		{
			rtInfo.eaEnd = eaAddress;
			//Output(" vftable: %08X-%08X, methods: %d\n", rtInfo.eaStart, rtInfo.eaEnd, rtInfo.uMethods);				
			return(TRUE);
		}
		else
		{
			//Output(" ******* 5\n");
			return(FALSE);
		}
	}
}

// Get relative jump target address
static ea_t GetRelJmpTarget(ea_t eaAddress)
{	
	BYTE bt = get_byte(eaAddress);
	if(bt == 0xEB)
	{
		bt = get_byte(eaAddress + 1);
		if(bt & 0x80)
			return(eaAddress + 2 - ((~bt & 0xFF) + 1));
		else
			return(eaAddress + 2 + bt);
	}
	else
	if(bt == 0xE9)
	{
		UINT dw = get_32bit(eaAddress + 1);
		if(dw & 0x80000000)
			return(eaAddress + 5 - (~dw + 1));
		else
			return(eaAddress + 5 + dw);
	}
	else
		return(BADADDR);
}

#define SN_constructor 1
#define SN_destructor  2
#define SN_vdestructor 3
#define SN_scalardtr   4
#define SN_vectordtr   5


// Try to identify and place known class member types
int VFTABLE::TryKnownMember(LPCTSTR lpszName, ea_t eaMember)
{
	int iType = 0;

	#define IsPattern(Address, Pattern) (find_binary(Address, Address+(SIZESTR(Pattern)/2), Pattern, 16, (SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW)) == Address)

	if(eaMember && (eaMember != BADADDR))
	{
		// Skip if it already has a name
		flags_t Flags = getFlags((ea_t) eaMember);
		if(!has_name(Flags) || has_dummy_name(Flags))
		{
			// Should be code
			if(isCode(Flags))
			{
				ea_t eaAddress = eaMember;

				// E9 xx xx xx xx   jmp   xxxxxxx
				BYTE Byte = get_byte(eaAddress);
				if((Byte == 0xE9) ||(Byte == 0xEB))
				{					
					return(TryKnownMember(lpszName, GetRelJmpTarget(eaAddress)));
				}
				else
				if(IsPattern(eaAddress, " "))
				{

				}
			}
			else
				msg(" %08X ** Not code at this member! **\n", eaMember);
		}
	}

	return(iType);
}


// Process vftable member functions
void VFTABLE::ProcessMembers(LPCTSTR lpszName, ea_t eaStart, ea_t eaEnd)
{
	//Output(" %08X to %08X\n", eaStart, eaEnd);

/*
	TODO: On hold for now.
	Do we really care about detected ctors and dtors?
    Is it helpful vs the problems of naming member functions?
*/

/*
	ea_t eaAddress = eaStart;

	while(eaAddress < eaEnd)
	{	
		ea_t eaMember;
		if(GetVerify32_t(eaAddress, eaMember))
		{
			// Missing/bad code?
			if(!get_func(eaMember))
			{
				//Output(" %08X ** No member function here! **\n", eaMember);				
				ua_code(eaMember);				
				add_func(eaMember, BADADDR);
			}

			TryKnownMember(lpszName, eaMember);
		}
		else
			Output(" %08X ** Failed to read member pointer! **\n", eaAddress);
	
		eaAddress += 4;
	};
*/
}