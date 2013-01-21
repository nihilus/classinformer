
// ****************************************************************************
// File: RTTI.h
// Desc: RTTI defs and support
//
// ****************************************************************************
#pragma once

namespace RTTI
{
	#pragma pack(push, 1)
	
	// ** All members assumed to be in IDA, not process space

	// std::type_info
	struct NOVTABLE type_info
	{
		type_info(){ ZeroMemory(this, sizeof(type_info)); }

		PVOID vftable;
	//private:
		PVOID _m_data;
		//char  _m_d_name[1];
		char  _m_d_name[MAXSTR]; // Mangled name (prefix: .?AV=classes, .?AU=structs)

		static BOOL IsValid(type_info *pIDA);		
		static BOOL DoStruct(type_info *pTypeInfo);		

		static LPSTR GetName(IN type_info *pIDA, OUT LPSTR pszBufer, int iSize);		

		// Returns TRUE if mangled name is a unknown type name		
		static inline BOOL IsTypeName(LPCSTR pszName){ return((*((PUINT) pszName) & 0xFFFFFF) == 0x413F2E /*".?A"*/); }
	};

	struct NOVTABLE PMD
	{
		int mdisp;	// 00 Member displacement
		int pdisp;  // 04 Vftable displacement
		int vdisp;  // 08 Displacement inside vftable		
	};

	struct NOVTABLE BaseClassDescriptor
	{
		BaseClassDescriptor(){ ZeroMemory(this, sizeof(BaseClassDescriptor)); }
		
		type_info *pTypeDescriptor;	// 00 Type descriptor of the class
		UINT numContainedBases;		// 04 Number of nested classes following in the Base Class Array
		PMD  pmd;					// 08 Pointer-to-member displacement info
		UINT attributes;			// 14 Flags, usually 0

		static BOOL DoStruct(IN BaseClassDescriptor *pBCD, OUT LPSTR pszBaseClassName);
	};
	
	struct NOVTABLE ClassHierarchyDescriptor
	{
		ClassHierarchyDescriptor(){ ZeroMemory(this, sizeof(ClassHierarchyDescriptor)); }		

		UINT signature;			// 00 Always zero?
		UINT attributes;		// 04 Bit 0 set = multiple inheritance, bit 1 set = virtual inheritance
		UINT numBaseClasses;	// 08 Number of classes in pBaseClassArray
		BaseClassDescriptor **pBaseClassArray; // 0C

		static BOOL DoStruct(ClassHierarchyDescriptor *pCHD);
	};	

	const UINT CHDF_MULTIPLE = (1 << 0);
	const UINT CHDF_VIRTUAL	 = (1 << 1);

	struct NOVTABLE CompleteObjectLocator
	{
		CompleteObjectLocator(){ ZeroMemory(this, sizeof(CompleteObjectLocator)); }		

		UINT signature;				// 00 Always zero ?
		UINT offset;				// 04 Offset of this vftable in the complete class
		UINT cdOffset;				// 08 Constructor displacement offset
		type_info *pTypeDescriptor;	// 0C TypeDescriptor of the complete class
		ClassHierarchyDescriptor *pClassDescriptor; // 10 Describes inheritance hierarchy

		static BOOL IsValid(CompleteObjectLocator *pCOL);		
		static BOOL DoStruct(CompleteObjectLocator *pCOL);		
	};
	#pragma pack(pop)

	void CreateStructDefs();	
	void ProcessVftable(ea_t eaVftable, ea_t eaEnd);		
}

