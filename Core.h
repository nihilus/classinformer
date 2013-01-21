
// ****************************************************************************
// File: Core.h
// Desc: 
//
// ****************************************************************************

extern void Output(LPCSTR format, ...);
extern BOOL HasAnteriorComment(ea_t ea);
extern void KillAnteriorComments(ea_t ea);
extern void FixDWORD(ea_t eaAddress);
extern int  AddStrucMember(struc_t *sptr, char *name, ea_t offset, flags_t flag, typeinfo_t *type, asize_t nbytes);
extern LPCTSTR GetDisasmText(ea_t ea);
extern LPSTR GetPlainClassName(IN LPSTR pszMangled, OUT LPSTR pszOutput);

// IDA icons
#define ICON_SI		 152
#define ICON_MI		 162
#define ICON_VI		 163
#define ICON_MI_VI	 164
#define ICON_RTCI	 70
#define ICON_NAMED   35
#define ICON_UNKNOWN 121

extern void AddTableEntry(int iIcon, ea_t eaVftable, UINT uMethodCount, LPCTSTR lpszFormat, ...);
extern void SetUnknown(ea_t ea, size_t size);

extern BOOL bAudioOnDone, bOverwriteComents, bPlaceStructs;

