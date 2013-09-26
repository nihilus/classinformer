
// ****************************************************************************
// File: Core.cpp
// Desc: 
//
// ****************************************************************************
#include "stdafx.h"
#include "resource.h"
#include "ContainersInl.h"
#include "Core.h"
#include "Vftable.h"
#include "RTTI.h"
#include "RTCI.h"
#include <WaitBoxEx.h>
#include <SegmentSelectBox.h>
#include <HelpURL.h>

//#define LOG_FILE

const static char NETNODE_NAME[] = {"$ClassInformer_node"};
const char DATA_TAG  = 'A';
const char TABLE_TAG = 'S';

// Our netnode value indexes
enum NETINDX
{
    NIDX_VERSION,   // ClassInformer version
    NIDX_COUNT      // Table entry count
};


// VFTable entry container (fits in a netnode MAXSPECSIZE size)
#pragma pack(push, 1)
struct TBLENTRY
{ 
    ea_t  eaVftable;	
	asize_t  astMethodCount;
    short sIcon;
    WORD  wTextSize;    
	char  szName[MAXSPECSIZE - (sizeof(ea_t) + sizeof(asize_t) + sizeof(short) + sizeof(WORD))]; // IDA MAXSTR = 1024
};
#pragma pack(pop)

struct CODEXTN { ea_t Start, End; };

// UI Options
static SBITFLAG BitF;
const static WORD PLACE_STRUCTS			= BitF.Next(); // Build RTTI & RTCI structures
const static WORD FIND_CTOR_DTOR		= BitF.Next(); // Find and fix static/global ctors/dtors
const static WORD REPORT_ALL_VFTABLES	= BitF.Next(); // Log all suspected vftables
const static WORD OVERWRITE_COMMENTS	= BitF.Next(); // Overwrite comments switch
const static WORD DEBUG_TRACE	        = BitF.Next(); // Echo detailed info to debug channel
const static WORD AUDIO_NOTIFY_DONE		= BitF.Next(); // Do an auto notification after processing is done.

// === Function Prototypes ===
static void ScanForVFTables();
static BOOL ProcessStaticTables();
static BOOL TryVFTable(ea_t &reaRdataLoc);
static void StoreList();
static void ShowEndStats();
static LPCTSTR TimeString(TIMESTAMP Time);
void Output(LPCSTR format, ...);

// === Data ===
TIMESTAMP s_StartTime	        = 0;
static UINT uCodeSections       = 0;
static UINT uStaticCtorNameSeq  = 0;
static UINT uStaticDtorNameSeq  = 0;
static UINT uStartingFunctions  = 0;
static UINT uStaticCtorDtorNSeq = 0;
static netnode *pcNNode         = NULL;
static HMODULE hModule          = NULL;
static CODEXTN *pCodeArray      = NULL;
static FILE    *hLogFile		= NULL;
static SEGBOX::SEGLIST cCodeSeg;
static SEGBOX::SEGLIST cDataSeg;
static cWaitBoxEx MyWaitBox;

// Options
BOOL bDebugOutput      = FALSE;
BOOL bAudioOnDone      = TRUE;
BOOL bFixGobalStatic   = TRUE;
BOOL bOverwriteComents = FALSE;
BOOL bPlaceStructs	   = TRUE;
BOOL bLogAllVFTables   = TRUE;

// Stats
static UINT uRTTI_VFTables  = 0;
static UINT uRTCI_VFTables  = 0;
static UINT uNamed_VFTables = 0;
static UINT uOther_VFTables = 0;

// Options dialog
static const char szOptionDialog[] =
{	
	"BUTTON YES* Continue\n" // 'Continue' instead of 'okay'
	
	// -- Help block
	"HELP\n"
	"\"Class Informer PlugIn\": " 
	"An IDA Pro Win32 class vftable finder w/RTTI & MFC RTCI parser, namer, and fixer plug-in.\n"	
	"By Sirmabus\n"
	"================================================================================\n\n"
	
	"This plug-in scans an IDB for C++ vftables with type info et al.\n"
	"It is to aid reversing by identifying and building C++ class information,\n"
	"with a positive byproduct of some additional clean up.\n"

	"It is currently designed around Microsoft Visual C++, 32bit complied targets.\n"
	"Will have unpredictable results when run on other.\n\n"

	"How it works:\n"
	"1) Scans the \".rdata\" segment for vftables.\n"
	"2) As it finds and validates them, it parses any existing RTTI or RTCI type info and places containers for them.\n"
	"3) It will then rename the vftable with the type (or based on user name) if it finds one.\n"
	"4) Finally, outputs this information in list for browsing.\n"
	"   Click on list entry to jump to the vftable.\n\n"

	"Note: Placing the RTTI/RTCI structures in IDA can take a long time for large IDBs.\n"
	"If you just want a list, you can uncheck the \"place structures\" option for much faster processing time.\n\n"

	"Based on: \"Reversing Microsoft Visual C++ Part II: Classes, Methods and RTTI\", by igorsk.\n\n"

	"See \"Class_Informer.txt\" for more help.\n"

	"Support forum: http://www.macromonkey.com/bb/viewforum.php?f=65\n"
	"ENDHELP\n"	

	// -- Title
	"<Class Informer Plug-in>\n"

	// -- Message text
	"- Version: %A, build %A, by Sirmabus -\n"
	"Warning: Backup your IDB first before running this.  \n\n"

	"Options:\n"
	
	// ** Order must match option bit flags above	

	// Tooltip then label	
	"<#Place type structures.\nWas very slow do to a bug in 1.0, now only about 1x slower.#Build type containers.:C>\n"
	"<#Locate, fix, and label static/global class constructors and destructors.#Find, fix, and label static/global ctors and dtors.       :C>\n"
	"<#Report all vftables found even if we don't have a name for them.#Report all vftables found.:C>\n"    
	"<#Overwrite existing anterior comments with our own as needed.\nOnly an issue if you added your own anterior comments to vftables.#Overwrite anterior comments.:C>\n"		    
	"<#Dumps detailed vftable information to the debug channel (requires debug viewer).#Verbose output to debug channel.:C>\n"
	"<#Make a notification sound when finished.#Audio notification on completion.:C>>\n"

	// Segment select buttons
	"\n\n<#Choose the code segment(s) where class references will reside.\nElse use the first \".text\" segment by default.#Choose CODE segments:B:1:18::>  "
	"<#Choose the data segment(s) to scan for vftables.\nElse use the first \".rdata\" segment by default.#Choose RDATA segments:B:2:19::>\n"
	"                         <#Click to open Sirmabus IDA Pro plug-in support page.#Open support forum:B:2:18::>\n"
};

// List box defs
static const char LBTITLE[] = {"[Class Informer]"};
static const UINT LBCOLUMNCOUNT = 3;
static const int aListBColumnWidth[LBCOLUMNCOUNT] = {9|CHCOL_HEX, 3, 300};
static const LPCSTR s_aColumnHeader[LBCOLUMNCOUNT] = 
{
	"Vftable",	
	"Method count",
	"Class & structure info"
};

static void FreeWorkingData()
{
    if(pCodeArray)
    { 
        qfree(pCodeArray);
        pCodeArray = NULL;
    }    

	cCodeSeg.clear();
	cDataSeg.clear();

    if(pcNNode)
    {
        delete pcNNode;
        pcNNode = NULL;
    }
}

// Initialize
void CORE_Init()
{
    // Catch if in the future the SDK changes this "netnode.hpp"
    C_ASSERT(MAXSPECSIZE == 1024);
    C_ASSERT(sizeof(TBLENTRY) <= MAXSPECSIZE);

	// Add structure definitions to IDA
	RTTI::CreateStructDefs();
	RTCI::CreateStructDefs();
}

// Uninitialize
void CORE_Exit()
{			
	FreeWorkingData();   

    if(hLogFile) 
    {
        qfclose(hLogFile);
        hLogFile = NULL;
    }
		
	if(hModule)	
		PlaySound(NULL, 0, 0);
}


// Init new netnode storage
inline static void NewNetnodeStore()
{
    // Kill any existing store data first
    pcNNode->supdel_all(DATA_TAG);
    pcNNode->supdel_all(TABLE_TAG);
   
    // Init defaults
    pcNNode->altset_idx8(NIDX_VERSION, MY_VERSION, DATA_TAG);
    pcNNode->altset_idx8(NIDX_COUNT,   0,          DATA_TAG);
}

inline WORD GetStoreVersion(){ return((WORD) pcNNode->altval_idx8(NIDX_VERSION, DATA_TAG)); }
inline asize_t GetTableCount(){ return(pcNNode->altval_idx8(NIDX_COUNT, DATA_TAG)); }
inline BOOL SetTableCount(asize_t astCount){ return(pcNNode->altset_idx8(NIDX_COUNT, astCount, DATA_TAG)); }
inline BOOL GetTableEntry(TBLENTRY &rEntry, asize_t astIndex){ return(pcNNode->supval(astIndex, &rEntry, sizeof(TBLENTRY), TABLE_TAG) > 0); }
inline BOOL SetTableEntry(TBLENTRY &rEntry, asize_t astIndex){ return(pcNNode->supset(astIndex, &rEntry, (offsetof(TBLENTRY, szName) + rEntry.wTextSize), TABLE_TAG)); }


static void idaapi ForumBtnHandler(TView *fields[], int code)
{
    cURLHelp::OpenSupportForum();
}

static UINT CALLBACK LB_OnGetLineCount(PVOID pObj){ return (UINT)min(GetTableCount(),MAXUINT_PTR); }
static void CALLBACK LB_OnMakeLine(PVOID pObj, UINT n, char * const *ppCell)
{	
	if(n == 0)
	{
		for(UINT i = 0; i < LBCOLUMNCOUNT; i++)
			strncpy(ppCell[i], s_aColumnHeader[i], (MAXSTR - 1));
	}
	else
	{
        TBLENTRY Entry; 
        GetTableEntry(Entry, (n - 1));
		sprintf(ppCell[0], "%08X", Entry.eaVftable);
        sprintf(ppCell[1], "%8u", Entry.astMethodCount);
        memcpy(ppCell[2], Entry.szName, Entry.wTextSize);		
	}
}

static int CALLBACK LB_OnGetIcon(PVOID pObj, UINT n)
{
	//return(n);
	if(n == 0)
	    return(0);
	else
    {
        TBLENTRY Entry; 
        GetTableEntry(Entry, (n - 1));
		return((int) Entry.sIcon);
    }
}

static void CALLBACK LB_OnSelect(PVOID pObj, UINT n)
{ 
    TBLENTRY Entry; 
    GetTableEntry(Entry, (n - 1));
    jumpto(Entry.eaVftable);
}
static void CALLBACK LB_OnClose(PVOID pObj) { FreeWorkingData(); }

// Add an entry to the vftable list
void AddTableEntry(int iIcon, ea_t eaVftable, asize_t astMethodCount, LPCTSTR lpszFormat, ...)
{
    TBLENTRY Entry;          
    Entry.eaVftable     = eaVftable;    
    Entry.astMethodCount  = astMethodCount;
    Entry.sIcon         = iIcon;
		
    Entry.szName[SIZESTR(Entry.szName)] = 0;
	va_list vl;
	va_start(vl, lpszFormat);
	_vsntprintf(Entry.szName, SIZESTR(Entry.szName), lpszFormat, vl);	
	va_end(vl);
    Entry.wTextSize = (strlen(Entry.szName) + 1);
       
    asize_t astCount = GetTableCount();
    SetTableEntry(Entry, astCount);
    SetTableCount(++astCount);       
}

// Handler for choose code and data segment buttons
static void idaapi ChooseBtnHandler(TView *fields[], int code)
{
	if(code == 1)
		cCodeSeg = SEGBOX::Select(" Choose CODE segments:", SEGBOX::eSGST_CODE);
	else
	if(code == 2)
		cDataSeg = SEGBOX::Select(" Choose RDATA segments:", SEGBOX::eSGST_DATA);
}

// Plug-in process
void CORE_Process(int iArg)
{	
    char szVersion[16];
    sprintf(szVersion, "%u.%02u", HIBYTE(MY_VERSION), LOBYTE(MY_VERSION));
	msg("\n== Class Informer plug-in: v: %s, BD: %s, By Sirmabus ==\n", szVersion, __DATE__); 
	if(!autoIsOk())
	{
		msg("** Must wait for IDA to finish processing before starting plug-in! **\n*** Aborted ***\n\n");
		return;
	}	
					
    FreeWorkingData();
	uCodeSections     = 0;
	uStaticCtorNameSeq  = 0;
	uStaticDtorNameSeq  = 0;
	uStaticCtorDtorNSeq = 0;	   
	bDebugOutput		= FALSE;
	bAudioOnDone		= TRUE;
	bFixGobalStatic		= TRUE;
	bOverwriteComents	= FALSE;
	bPlaceStructs		= TRUE;
	bLogAllVFTables		= TRUE;	
	uRTTI_VFTables		= 0;
	uRTCI_VFTables		= 0;
	uNamed_VFTables		= 0;
	uOther_VFTables		= 0;
	uStartingFunctions  = get_func_qty();	
    
    // Create storage netnode
    if(!(pcNNode = new netnode(NETNODE_NAME, SIZESTR(NETNODE_NAME), TRUE)))
    {
        QASSERT(66, FALSE);
        return;
    }         
    
    asize_t astTableCount   = GetTableCount();
    WORD wStoreVersion = GetStoreVersion();
    BOOL bStorageExists = ((wStoreVersion == MY_VERSION) && (astTableCount > 0));
   
    // Ask if we should use storage or process again
    if(bStorageExists)
        bStorageExists = (askyn_c(1, "TITLE ClassInfomer %s\nHIDECANCEL\nUse previously stored result?        ", szVersion) == 1);
    else
    if((wStoreVersion != MY_VERSION) && (astTableCount > 0))
        Output("** Storage data version missmatch! **\n");
 	  
    if(!bStorageExists)
    {        
        NewNetnodeStore();
        
        // Verify MSVS target    
	    {
		    int iSigCount = get_idasgn_qty();
		    int i = 0;
		    for(; i < iSigCount; i++)
		    {
			    char szDesc[MAXSTR];
			    szDesc[0] = szDesc[MAXSTR-1] = 0;
			    get_idasgn_desc(i, szDesc, (MAXSTR-1), NULL, 0);
			    //Output("[%d] \"%s\"\n", i, szDesc);
			    if(strncmp(szDesc, "vc32", SIZESTR("vc32")) == 0)
				    break;
		    }

		    // Show warning, continue yes/no dialog
		    if(i >= iSigCount)
		    {
			    msg("* Appears not to be a MSVC target *\n");

			    int iResult = askbuttons_c(NULL, NULL, NULL, 0, "TITLE Class Informer plug-in:\nHIDECANCEL\nThis DB doesn't appear to be a Microsoft compiled target I know about.\n\nThis plug-in only understands MSVC class information currently.\nRunning it on other targets, like Borland compiled, etc., will have unpredicted results.\n\n Are you really sure you want to continue anyhow?");
			    if(iResult != 1)
			    {
				    msg("- Aborted -\n\n");
				    return;
			    }
		    }
	    }			

	    // Reset default options
	    bAudioOnDone = TRUE, bOverwriteComents = FALSE, bLogAllVFTables = TRUE, bFixGobalStatic = TRUE;
	    uRTTI_VFTables = uRTCI_VFTables = uNamed_VFTables = uOther_VFTables = 0;

	    // Do UI			
	    WORD wOptionFlags = 0;            
	    if(bDebugOutput)		wOptionFlags |= DEBUG_TRACE;		
	    if(bAudioOnDone)		wOptionFlags |= AUDIO_NOTIFY_DONE;
	    if(bFixGobalStatic)		wOptionFlags |= FIND_CTOR_DTOR;		
	    if(bOverwriteComents)	wOptionFlags |= OVERWRITE_COMMENTS;
	    if(bLogAllVFTables)		wOptionFlags |= REPORT_ALL_VFTABLES;
	    if(bPlaceStructs)		wOptionFlags |= PLACE_STRUCTS;		
	    {
		    cURLHelp cURLBtn("http://www.macromonkey.com/bb/viewtopic.php?f=65&p=5708");
		    int iUIResult = AskUsingForm_c(szOptionDialog, szVersion, __DATE__, &wOptionFlags, ChooseBtnHandler,ChooseBtnHandler, ForumBtnHandler);
		    if(!iUIResult)
		    {			
			    msg("- Canceled -\n\n");
			    return;
		    }		
	    }        
	    bDebugOutput	  = ((wOptionFlags & DEBUG_TRACE) != 0);
	    bAudioOnDone	  = ((wOptionFlags & AUDIO_NOTIFY_DONE) != 0);		
	    bFixGobalStatic	  = ((wOptionFlags & FIND_CTOR_DTOR) != 0);
	    bOverwriteComents = ((wOptionFlags & OVERWRITE_COMMENTS) != 0);
	    bLogAllVFTables	  = ((wOptionFlags & REPORT_ALL_VFTABLES) != 0);
	    bPlaceStructs	  = ((wOptionFlags & PLACE_STRUCTS) != 0); 
 
	    // Use defaults if no user segment selection
	    if(cCodeSeg.empty())
	    {
		    if(segment_t *pSeg = get_segm_by_name(".text"))
			    cCodeSeg.push_front(pSeg);
	    }
	    if(cDataSeg.empty())
	    {
		    if(segment_t *pSeg = get_segm_by_name(".rdata"))
			    cDataSeg.push_front(pSeg);
            if(segment_t *pSeg = get_segm_by_name(".data"))
                cDataSeg.push_front(pSeg);
	    }

	    if(cCodeSeg.size() && cDataSeg.size())
	    {
		    // Create a code extents array for speed
		    {
			    uCodeSections = cCodeSeg.size();
			    pCodeArray    = (CODEXTN *) qalloc_or_throw(sizeof(CODEXTN) * uCodeSections);

			    msg("\nUsing code segments:\n");
			    msg("------Name--Address-----------Size-----Flags--Class-\n");
			    int iIndex = 0;
			    SEGBOX::SEGLIST::iterator i;
			    for(i = cCodeSeg.begin(); i != cCodeSeg.end(); i++, iIndex++)
			    {
				    // Show segment info
				    {
					    segment_t *pCodeSeg = (*i);

					    // Segment name
					    char szName[32];
					    if(get_true_segm_name(pCodeSeg, szName, SIZESTR(szName)) <= 0)					
						    qstrncpy(szName, ".unknown", sizeof(".unknown"));

					    // Segment class name
					    char szClass[32];
					    if(get_segm_class(pCodeSeg, szClass, SIZESTR(szClass)) <= 0)
						    qstrncpy(szClass, "none", sizeof("none"));

					    // Permission flags
					    char szFlags[4] = {"..."};
					    if(pCodeSeg->perm & SEGPERM_READ)
						    szFlags[0] = 'R';
					    if(pCodeSeg->perm & SEGPERM_WRITE)
						    szFlags[1] = 'W';
					    if(pCodeSeg->perm & SEGPERM_EXEC)
						    szFlags[2] = 'E';

					    msg("[%d] \"%s\" %08X-%08X %08X %s    %s\n", iIndex, szName, pCodeSeg->startEA, pCodeSeg->endEA, pCodeSeg->size(), szFlags, szClass);
				    }

				    pCodeArray[iIndex].Start = (*i)->startEA;
				    pCodeArray[iIndex].End   = (*i)->endEA;
			    }
			    msg("\n");
		    }													

		    //msg("Working: .text: (%08X - %08X), .rdata: (%08X - %08X)..\n", s_pCodeSeg->startEA,s_pCodeSeg->endEA, s_pRDataSeg->startEA,s_pRDataSeg->endEA);
		    msg("Working..\n");
		    s_StartTime = GetTimeStamp();
		    if(MyWaitBox.IsQtQUI())
			    MyWaitBox.Begin("<Class Informer PlugIn> working...");
		    else
			    MyWaitBox.Begin("<Class Informer> working...\n\n\n<Press Pause/Break key to abort>");			
		    if(bFixGobalStatic)
		    {				
			    // Process global and static ctor sections
			    Output(" \n");
			    Output("Processing static/global ctor & dtor tables.\n");
			    //Output("Could cause IDA to do substantial analysis if tables are large..\n");
			    if(ProcessStaticTables())
			    {
				    Output("- Aborted -\n\n");
				    ShowEndStats();
				    MyWaitBox.End();
				    refresh_idaview_anyway();
				    return;
			    }
			    else
				    Output("Processing time: %s.\n", TimeString(GetTimeStamp() - s_StartTime));
		    }								

		    // Scan through data segment(s)..
		    Output(" \n");
		    if(bDebugOutput) Trace("= Vftable address = Method Count == Class/struct names and hierarchy ========================\n");
		    msg("Scanning data segments..\n");			

		    // Scan for vftables and process
		    ScanForVFTables();			
    		
		    // Done       
            // ** Must be before "choose2()" window, if inside will have tab page issues..
		    MyWaitBox.End();
		    refresh_idaview_anyway();

            if(bAudioOnDone)
            {                
                if(!hModule)
                    GetModuleHandleEx((GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS), (LPCTSTR) &CORE_Process, &hModule);
                if(hModule)
                    PlaySound(MAKEINTRESOURCE(IDR_DONE_WAVE), hModule, (SND_RESOURCE | SND_ASYNC));
            }

            Output("\nDone.\n");
            ShowEndStats();

            if(!autoIsOk())
            {
                msg("IDA updating, please wait..");
                autoWait();
                msg(" done.\n");
            }        
            msg("\n");
        }     
        // No code, and, or data segments to process error
        else
        {		
            if(cCodeSeg.empty())
                Output("** Could find the default code segment \".text\" **!\n");
            if(cDataSeg.empty())
                Output("** Could find the default data segment \".rdata\" **!\n");

            Output("Try selecting the code, and, or data segments manually.\n");
            return;
        }       
    }

	// Show list result window		
    if(GetTableCount() > 0)
    {
	    choose2(0,			// Non-modal window
	    -1, -1, -1, -1,		// Window position
	    NULL,			    // LPARM
	    LBCOLUMNCOUNT,		// Number of columns
	    aListBColumnWidth,  // Widths of columns
	    LB_OnGetLineCount,	// Function that returns number of lines
	    LB_OnMakeLine,  	// Function that generates a line
	    LBTITLE,			// Window title
	    160, 	 			// Icon for the window
	    0,					// Starting line
	    NULL,				// "kill" callback
	    NULL,				// "new" callback
	    NULL,				// "update" callback
	    NULL,				// "edit" callback
	    LB_OnSelect,		// Function to call when the user pressed Enter
	    LB_OnClose,			// Function to call when the window is closed
	    NULL,				// Popup menu items
	    LB_OnGetIcon);	    // Line icon function			
    }
}

// Fix, label and comment static/global ctor table up
static void SetCtorTable(ea_t eaTableStart, ea_t eaTableEnd)
{
	// Make sure table values are all 32bit
	ea_t eaEntry = eaTableStart;
	while(eaEntry <= eaTableEnd)
	{							
		FixDWORD(eaEntry);

		// Might fix missing/messed stubs
		if(ea_t eaFunc = get_32bit(eaEntry))
		{		
			// Make address code
			ua_code(eaFunc);

			// Make it a function			
			add_func(eaFunc, BADADDR);		
		}

		eaEntry += 4;
	};

	// Name it
	flags_t Flags = getFlags(eaTableStart);
	if(!has_name(Flags) || has_dummy_name(Flags))
	{
		char szName[MAXSTR]; szName[0] = szName[MAXSTR-1] = 0;
		qsnprintf(szName, (MAXSTR-1), "aStaticCtorTableStart%02d", uStaticCtorNameSeq);
		if(!set_name(eaTableStart, szName, (SN_NON_AUTO | SN_NOWARN)))
		{
		//msg("%08X \"%s\" SETNAME FAIL.\n", (ea_t) eaTableStart, szName);

			// If it fails use the first sequence that works					
			for(int i = 0; i < 1000000; i++)
			{	
				char szTempName2[MAXSTR];
				qsnprintf(szTempName2, (MAXSTR-1), "%s_%d", szName, i);
				if(set_name(eaTableStart, szTempName2, (SN_NON_AUTO | SN_NOWARN)))
					break;
			}
		}
	}	

	Flags = getFlags(eaTableEnd);
	if(!has_name(Flags) || has_dummy_name(Flags))
	{
		char szName[MAXSTR];
		szName[0] = szName[MAXSTR-1] = 0;
		qsnprintf(szName, (MAXSTR-1), "aStaticCtorTableEnd%02d", uStaticCtorNameSeq);
		if(!set_name(eaTableEnd, szName, (SN_NON_AUTO | SN_NOWARN)))
		{
		//msg("%08X \"%s\" SETNAME FAIL.\n", (ea_t) eaTableEnd, szName);
			for(int i = 0; i < 1000000; i++)
			{	
				char szTempName2[MAXSTR];
				qsnprintf(szTempName2, (MAXSTR-1), "%s_%d", szName, i);
				if(set_name(eaTableEnd, szTempName2, (SN_NON_AUTO | SN_NOWARN)))
					break;
			}
		}
	}

	// Comment never overwrite because it might be the segment	
	if(!HasAnteriorComment(eaTableStart))
		add_long_cmt(eaTableStart, true, "");

	uStaticCtorNameSeq++;
}

// "" dtor
static void SetDtorTable(ea_t eaTableStart, ea_t eaTableEnd)
{
	// Make sure table values are all 32bit
	ea_t eaEntry = eaTableStart;
	while(eaEntry <= eaTableEnd)
	{							
		FixDWORD(eaEntry);

		// Might fix missing/messed stubs
		if(ea_t eaFunc = get_32bit(eaEntry))
		{		
			// Make address code
			ua_code(eaFunc);

			// Make it a function			
			add_func(eaFunc, BADADDR);		
		}

		eaEntry += 4;
	};

	// Name it
	flags_t Flags = getFlags(eaTableStart);
	if(!has_name(Flags) || has_dummy_name(Flags))
	{
		char szName[MAXSTR];
		szName[0] = szName[MAXSTR-1] = 0;
		qsnprintf(szName, (MAXSTR-1), "aStaticDtorTableStart%02d", uStaticDtorNameSeq);
		if(!set_name(eaTableStart, szName, (SN_NON_AUTO | SN_NOWARN)))
		{
		//msg("%08X \"%s\" SETNAME FAIL.\n", (ea_t) eaTableStart, szName);
			for(int i = 0; i < 1000000; i++)
			{	
				char szTempName2[MAXSTR];
				qsnprintf(szTempName2, (MAXSTR-1), "%s_%d", szName, i);
				if(set_name(eaTableStart, szTempName2, (SN_NON_AUTO | SN_NOWARN)))
					break;
			}
		}
	}	

	Flags = getFlags(eaTableEnd);
	if(!has_name(Flags) || has_dummy_name(Flags))
	{
		char szName[MAXSTR];
		szName[0] = szName[MAXSTR-1] = 0;
		qsnprintf(szName, (MAXSTR-1), "aStaticDtorTableEnd%02d", uStaticDtorNameSeq);
		if(!set_name(eaTableEnd, szName, (SN_NON_AUTO | SN_NOWARN)))
		{
		//msg("%08X \"%s\" SETNAME FAIL.\n", (ea_t) eaTableEnd, szName);
			for(int i = 0; i < 1000000; i++)
			{	
				char szTempName2[MAXSTR];
				qsnprintf(szTempName2, (MAXSTR-1), "%s_%d", szName, i);
				if(set_name(eaTableEnd, szTempName2, (SN_NON_AUTO | SN_NOWARN)))
					break;
			}
		}
	}

	// Comment, never overwrite because it might be the segment	
	if(!HasAnteriorComment(eaTableStart))
		add_long_cmt(eaTableStart, true, "");	

	uStaticDtorNameSeq++;
}

// "" for when we are uncertain of ctor or dtor table
static void SetCtorDtorTable(ea_t eaTableStart, ea_t eaTableEnd)
{
	msg(" SetCtorDtorTable: %08X %08X\n", eaTableStart, eaTableEnd);

	// Make sure table values are all 32bit
	ea_t eaEntry = eaTableStart;
	while(eaEntry <= eaTableEnd)
	{							
		FixDWORD(eaEntry);

		// Might fix missing/messed stubs
		if(ea_t eaFunc = get_32bit(eaEntry))
		{		
			// Make address code
			ua_code(eaFunc);

			// Make it a function			
			add_func(eaFunc, BADADDR);		
		}

		eaEntry += 4;
	};

	// Name it
	flags_t Flags = getFlags(eaTableStart);
	if(!has_name(Flags) || has_dummy_name(Flags))
	{
		char szName[MAXSTR];
		szName[0] = szName[MAXSTR-1] = 0;
		qsnprintf(szName, (MAXSTR-1), "aStaticCtorDtorTableStart%02d", uStaticCtorDtorNSeq);
		if(!set_name(eaTableStart, szName, (SN_NON_AUTO | SN_NOWARN)))
		{
		//msg("%08X \"%s\" SETNAME FAIL.\n", (ea_t) eaTableStart, szName);
			for(int i = 0; i < 1000000; i++)
			{	
				char szTempName2[MAXSTR];
				qsnprintf(szTempName2, (MAXSTR-1), "%s_%d", szName, i);
				if(set_name(eaTableStart, szTempName2, (SN_NON_AUTO | SN_NOWARN)))
					break;
			}
		}
	}	

	Flags = getFlags(eaTableEnd);
	if(!has_name(Flags) || has_dummy_name(Flags))
	{
		char szName[MAXSTR];
		szName[0] = szName[MAXSTR-1] = 0;
		qsnprintf(szName, (MAXSTR-1), "aStaticCtorDtorTableEnd%02d", uStaticCtorDtorNSeq);
		if(!set_name(eaTableEnd, szName, (SN_NON_AUTO | SN_NOWARN)))
		{
		//msg("%08X \"%s\" SETNAME FAIL.\n", (ea_t) eaTableEnd, szName);
			for(int i = 0; i < 1000000; i++)
			{	
				char szTempName2[MAXSTR];
				qsnprintf(szTempName2, (MAXSTR-1), "%s_%d", szName, i);
				if(set_name(eaTableEnd, szTempName2, (SN_NON_AUTO | SN_NOWARN)))
					break;
			}
		}
	}
	
	// Comment, never overwrite because it might be the segment	
	if(!HasAnteriorComment(eaTableStart))
		add_long_cmt(eaTableStart, true, "");

	uStaticCtorDtorNSeq++;
}

// Process _cinit() functions for static/global ctor tables
static BOOL ProcessCinit(LPCTSTR pszName)
{
	BOOL bFound = FALSE;

	ea_t eaAddress = get_name_ea(BADADDR, pszName);
	if(eaAddress != BADADDR)
	{
		Output("%08X \"%s\" found.\n", eaAddress, pszName);

		if(func_t *pFunc = get_func(eaAddress))
		{			
			if(pFunc->startEA == eaAddress)
			{				
				ea_t eaPosition = pFunc->startEA;
				do
				{
					// mov     esi, offset dword_135A8EC -- Start
					// mov     eax, esi                 
					// mov     edi, offset dword_137714C -- End
					// cmp     eax, edi
					//
					eaPosition = find_binary(eaPosition, pFunc->endEA, "BE ? ? ? ? 8B C6 BF ? ? ? ? 3B C7", 16, (SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW));
					if(eaPosition && (eaPosition != BADADDR))
					{
						//Output("%08X \"__cinit()\" pattern found.\n", eaPosition);
						ea_t eaTableStart = get_32bit(eaPosition + 1); // "BE ? ? ? ?"
						ea_t eaTableEnd   = get_32bit(eaPosition + 8); // "BE ? ? ? ? 8B C6 BF"
						if((eaTableStart > 0xFFFF) && (eaTableEnd > 0xFFFF))
						{
							// Should be in the same segment
							if(getseg(eaTableStart) == getseg(eaTableEnd))
							{
								msg("%08X to %08X static/global \"_cinit()\" ctor table located <click me>.\n", eaTableStart, eaTableEnd);
								if(bDebugOutput) Trace("%08X to %08X static/global \"_cinit()\" ctor table located.\n", eaTableStart, eaTableEnd);
								SetCtorTable(eaTableStart, eaTableEnd);
								bFound = TRUE;
							}
						}

						eaPosition +=16;
					}									

				}while(eaPosition && (eaPosition != BADADDR));
				
				eaPosition = pFunc->startEA;
				do 
				{				
					// mov ecx, offset -- Start 
					// mov edi, offset -- End
					//
					eaPosition = find_binary(eaPosition, pFunc->endEA, "B9 ? ? ? ? BF ? ? ? ?", 16, (SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW));
					if(eaPosition && (eaPosition != BADADDR))
					{
						//Output("%08X \"__cinit()\" pattern found.\n", eaPosition);
						ea_t eaTableStart = get_32bit(eaPosition + 1); // B9 ? ? ? ?
						ea_t eaTableEnd   = get_32bit(eaPosition + 5+1); // BF ? ? ? ?
						if((eaTableStart > 0xFFFF) && (eaTableEnd > 0xFFFF))
						{							
							if(getseg(eaTableStart) == getseg(eaTableEnd))
							{
								msg("%08X to %08X static/global \"_cinit()\" ctor table located <click me>.\n", eaTableStart, eaTableEnd);
								if(bDebugOutput) Trace("%08X to %08X static/global \"_cinit()\" ctor table located.\n", eaTableStart, eaTableEnd);
								SetCtorTable(eaTableStart, eaTableEnd);							
								bFound = TRUE;
							}
						}					

						eaPosition += 12;
					}

				}while(eaPosition && (eaPosition != BADADDR));
			}
			else
				//Output("%08X ** \"%s\" found, but not function entry! **\n", eaAddress, pszName);
				Output("   address not a function entry.\n");
		}
		else
			//Output("%08X \"%s\" found, but not a function.\n", eaAddress, pszName);
			Output("   address not a function.\n");
	}
	
	return(bFound);
}

// Process "_initterm" type references
static BOOL ProcessInitterm(LPCTSTR pszName)
{
	BOOL bFound = FALSE;

	// Look for it by name
	ea_t eaAddress = get_name_ea(BADADDR, pszName);
	if(eaAddress != BADADDR)
	{
		Output("%08X \"%s\" found.\n", eaAddress, pszName);

		if(func_t *pFunc = get_func(eaAddress))
		{			
			if(pFunc->startEA == eaAddress)
			{				
				// Iterate xrefs
				ea_t eaXRef = get_first_fcref_to(eaAddress);
				while(eaXRef && (eaXRef != BADADDR))
				{
					//Output(" \n");
					//Output("  %08X \"%s\" Xref\n", eaXRef, pszName);
										
					if(isCode(getFlags(eaXRef)))
					{
						ea_t eaTableStart = BADADDR;
						ea_t eaTableEnd   = BADADDR;
						// Special case for "__initterm". eax offset, push offset
						BOOL bLookEAX = (qstrcmp("__initterm", pszName) == 0);
											
						// Look above it for the two table offsets
						ea_t eaUpperLimit = (eaXRef - 24);
						ea_t eaPrevItem = prev_head(eaXRef, eaUpperLimit);
						while(eaPrevItem && (eaPrevItem != BADADDR))
						{											
							// TODO: Use instruction flags instead of string compares?
							LPCTSTR pszDis = GetDisasmText(eaPrevItem);
							//Output("  %08X \"%s\", bLookEAX: %d\n", eaPrevItem, pszDis, bLookEAX);

							if(eaTableStart == BADADDR)
							{
								if(bLookEAX)
								{
									if(strstr(pszDis, "mov     eax, offset "))
									{
										eaTableStart = get_32bit(eaPrevItem + 1);
									}
								}
								else
								{
									if(strstr(pszDis, "push    offset "))
									{
										eaTableStart = get_32bit(eaPrevItem + 1);
									}
								}
							}
							else
							{
								if(strstr(pszDis, "push    offset "))
								{
									eaTableEnd = get_32bit(eaPrevItem + 1);
								}
							}	
							//Output("    %08X %08X\n", eaTableStart, eaTableEnd);

							// Found both ends of table?
							if((eaTableEnd != BADADDR) && (eaTableStart != BADADDR))
							{			
								// Should be in the same segment
								if(getseg(eaTableStart) == getseg(eaTableEnd))
								{
									if(eaTableStart > eaTableEnd)
										swap_t(eaTableStart, eaTableEnd);

									// Try to determine if we are in dtor or ctor section if we can									
									char szFuncName[MAXSTR];
									if(get_func_name(eaXRef, szFuncName, SIZESTR(szFuncName)))
									{
										szFuncName[SIZESTR(szFuncName)] = 0;
										_strlwr(szFuncName);
								
										// Exit/dtor function?										
										if(strstr(szFuncName, "exit"))
										{
											msg("%08X to %08X static/global DTOR table located <click me>.\n", eaTableStart, eaTableEnd);
											if(bDebugOutput) Trace("%08X to %08X static/global dtor table located.\n", eaTableStart, eaTableEnd);											
											SetDtorTable(eaTableStart, eaTableEnd);
											bFound = TRUE;
											break;
										}
										else
										// Start/ctor?
										if(strstr(szFuncName, "start") || strstr(szFuncName, "cinit"))
										{
											msg("%08X to %08X static/global CTOR table located <click me>.\n", eaTableStart, eaTableEnd);
											if(bDebugOutput) Trace("%08X to %08X static/global CTOR table located.\n", eaTableStart, eaTableEnd);
											SetCtorTable(eaTableStart, eaTableEnd);
											bFound = TRUE;
											break;
										}
									}
									
									// Fall back to a generic assumption
									msg("%08X to %08X static/global CTOR/DTOR table located <click me>.\n", eaTableStart, eaTableEnd);
									if(bDebugOutput) Trace("%08X to %08X static/global CTOR/DTOR table located.\n", eaTableStart, eaTableEnd);
									SetCtorDtorTable(eaTableStart, eaTableEnd);
									bFound = TRUE;
									break;																									
								}
								else
								{
									msg("%08X ** Bad address range of %08X, %08X for \"%s\" type ** <click me>.\n", eaXRef, eaTableStart, eaTableEnd, pszName);
									if(bDebugOutput) Trace("%08X ** Bad address range of %08X, %08X for \"%s\" type **\n", eaXRef, eaTableStart, eaTableEnd, pszName);
									break;
								}
							}

							eaPrevItem = prev_head(eaPrevItem, eaUpperLimit);
						};					
					}			
					else					
						Output("  %08X ** \"%s\" xref is not code! **\n", eaXRef, pszName);								
					
					eaXRef = get_next_fcref_to(eaAddress, eaXRef);
				};			
			}
			else
				//Output("%08X ** \"%s\" found, but not function entry! **\n", eaAddress, pszName);
				Output("   address not a function entry.\n");
		}	
		else
			//Output("%08X \"%s\" type found, but not a function.\n", eaAddress, pszName);
			Output("   address not a function.\n");
	}
	
	return(bFound);
}


// Process global and static ctor data.
// With large and particular messy IDB's this processing can trigger some major reanalyzing
// Returns TRUE if aborted
static BOOL ProcessStaticTables()
{
	uStaticCtorNameSeq = uStaticDtorNameSeq = uStaticCtorDtorNSeq = 0;

	#define PSTEP ((int) 50 / 11)

	// Look for _cint() functions first
	ProcessCinit("__cinit");
		if(MyWaitBox.IsBreakProgress(PSTEP * 0)) return(TRUE);
	ProcessCinit("_cinit");
		if(MyWaitBox.IsBreakProgress(PSTEP * 1)) return(TRUE);
	// Same for stubs
	ProcessCinit("j___cinit");
		if(MyWaitBox.IsBreakProgress(PSTEP * 2)) return(TRUE);
	ProcessCinit("j__cinit");	
		if(MyWaitBox.IsBreakProgress(PSTEP * 3)) return(TRUE);

	// Process any references found of these
	ProcessInitterm("__initterm");
		if(MyWaitBox.IsBreakProgress(PSTEP * 4)) return(TRUE);
	ProcessInitterm("_initterm");
		if(MyWaitBox.IsBreakProgress(PSTEP * 5)) return(TRUE);
	ProcessInitterm("__initterm_e");
		if(MyWaitBox.IsBreakProgress(PSTEP * 6)) return(TRUE);
	ProcessInitterm("_initterm_e");
		if(MyWaitBox.IsBreakProgress(PSTEP * 7)) return(TRUE);
	//
	ProcessInitterm("j___initterm");
		if(MyWaitBox.IsBreakProgress(PSTEP * 8)) return(TRUE);
	ProcessInitterm("j__initterm");
		if(MyWaitBox.IsBreakProgress(PSTEP * 9)) return(TRUE);
	ProcessInitterm("j___initterm_e");
		if(MyWaitBox.IsBreakProgress(PSTEP * 10)) return(TRUE);
	ProcessInitterm("j__initterm_e");
		if(MyWaitBox.IsBreakProgress(0)) return(TRUE);

	//ProcessInitterm("__imp__initterm");	
	//ProcessInitterm("__imp__initterm_e");

	#undef PSTEP

	return(FALSE);
} 

// Returns TRUE if address in a selected code segment
static inline BOOL IsInCodeSeg(ea_t Address)
{
	for(UINT i = 0; i < uCodeSections; i++)
	{
		if((Address >= pCodeArray[i].Start) && (Address < pCodeArray[i].End))		
			return(TRUE);		
	}
	return(FALSE);
}


// Scan a data segment
static void ScanDataSegment(segment_t *pRDataSeg)
{	
	TIMESTAMP UpdateTime = GetTimeStampLow();	
	ea_t eaRdataPtr = pRDataSeg->startEA;

	// Show some segment info
	{
		// Segment name
		char szName[32];
		if(get_true_segm_name(pRDataSeg, szName, SIZESTR(szName)) <= 0)					
			qstrncpy(szName, ".unknown", sizeof(".unknown"));

		// Segment class name
		char szClass[16];
		if(get_segm_class(pRDataSeg, szClass, SIZESTR(szClass)) <= 0)
			qstrncpy(szClass, "none", sizeof("none"));

		// Permission flags
		char szFlags[4] = {"..."};
		if(pRDataSeg->perm & SEGPERM_READ)
			szFlags[0] = 'R';
		if(pRDataSeg->perm & SEGPERM_WRITE)
			szFlags[1] = 'W';
		if(pRDataSeg->perm & SEGPERM_EXEC)
			szFlags[2] = 'E';

		msg("Seg: \"%s\" %08X-%08X %08X, %s %s.\n", szName, pRDataSeg->startEA, pRDataSeg->endEA, pRDataSeg->size(), szFlags, szClass);
	}
	UINT uTotalStart = (uRTTI_VFTables + uRTCI_VFTables + uNamed_VFTables + uOther_VFTables);
	
	// Walk through this data segment looking for references in code sections
	const int SKIPCOUNT = 500;
	int iCounter = 0;
	while(eaRdataPtr <= pRDataSeg->endEA)
	{			
		// Should we look at raw DWORDs like this or first verify it's a valid DWORD?
		// And are we sure DWORD will always be at proper DWORD boundary? Could step one byte at the time
		// at a much slower rate.
		ea_t eaRefAddr = get_32bit(eaRdataPtr); // Basically "*((ea_t *) eaRdataPtr)"

		// Reference inside known code seg at least?    
		if(IsInCodeSeg(eaRefAddr))
		{	
			/*
			Output(" \n");
			Output("----------------------------------------------------------\n");
			Output("%08X .rdata.\n", eaRdataPtr);
			Output("%08X .text\n",   eaRefAddr);			
			*/

			//Trace("UPD: %f\n", (Time - UpdateTime));

			// Process vftable is there is one at this address and increment ptr accordingly	
			TryVFTable(eaRdataPtr);		
		}
		else
			eaRdataPtr += sizeof(UINT);

		// Break pressed  or clicked?				
		if(--iCounter <= 0)
		{
			iCounter = SKIPCOUNT;
			BOOL bAborted = FALSE;
			TIMESTAMP Time = GetTimeStampLow();	
			if((Time - UpdateTime) > 0.200)
			{
				UpdateTime = Time;
				bAborted = MyWaitBox.IsBreakProgress((int) (((double) (eaRdataPtr - pRDataSeg->startEA) / (double) (pRDataSeg->endEA - pRDataSeg->startEA)) * 100.0));				
			}
			else
				bAborted = MyWaitBox.IsBreak();

			if(bAborted)
			{
				Output("- Aborted -\n\n");
				break;
			}
		}							
	};
	
	msg("vftables here: %u\n\n", ((uRTTI_VFTables + uRTCI_VFTables + uNamed_VFTables + uOther_VFTables) - uTotalStart));
}

// Scan through data segment for vftables and process them..
static void ScanForVFTables()
{
	// Iterate through desired .rdata blocks..
	while(segment_t *pRDataSeg = cDataSeg.back())
	{
		ScanDataSegment(pRDataSeg);
		cDataSeg.pop_back();
	};
}


// If there is a vftable at this address then process it
// Returns TRUE on vftable found
static BOOL TryVFTable(ea_t &reaRdataLoc)
{
	//if(reaRdataLoc == 0xDBA7FC) // *** test a specific address test
	{
		// Look for vftable address, and grab some info on the way
		VFTABLE::tINFO tVftableInfo;
		if(VFTABLE::GetTableInfo(reaRdataLoc, tVftableInfo))
		{
			// Point past the vftable table for next pass
			reaRdataLoc = tVftableInfo.eaEnd;

			// Look for an RTTI entry first
			ea_t eaAssumedCOL;
			if(GetVerify32_t((tVftableInfo.eaStart - 4), eaAssumedCOL))
			{				
				// A valid RTTI "complete object locater" here?
				if(RTTI::CompleteObjectLocator::IsValid((RTTI::CompleteObjectLocator *) eaAssumedCOL))
				{		
					Trace("%08X %03d ", tVftableInfo.eaStart, tVftableInfo.uMethods);				
					RTTI::ProcessVftable(tVftableInfo.eaStart, tVftableInfo.eaEnd);		
					uRTTI_VFTables++;
					return(TRUE);
				}
			}

			// An RTCI type?
			if(RTCI::IsValid(tVftableInfo.eaStart))
			{			
				Trace("%08X %03d ", tVftableInfo.eaStart, tVftableInfo.uMethods);			
				RTCI::ProcessVftable(tVftableInfo.eaStart, tVftableInfo.eaEnd);
				uRTCI_VFTables++;
				return(TRUE);
			}	
		
			// Have more looser vftable detection now, so keep only one that have at more then one member
			if(tVftableInfo.uMethods > 1)
			{
				// Has a non-auto name?
				//** TODO: !isDwrd(Flags) removed from GetVFTableInfo(), should we check it here?
				if(has_user_name(getFlags(tVftableInfo.eaStart)))
				{					
					char szName[MAXSTR] = {0};			
					get_short_name(BADADDR, tVftableInfo.eaStart, szName, (MAXSTR - 1));			
					Trace("%08X %03d %s  [User named]\n", tVftableInfo.eaStart, tVftableInfo.uMethods, tVftableInfo.szName);
					AddTableEntry(ICON_NAMED, tVftableInfo.eaStart, tVftableInfo.uMethods, "%s  [User named]", tVftableInfo.szName);
					uNamed_VFTables++;			
					return(TRUE);
				}

				// Other vftables
				uOther_VFTables++;
				if(bLogAllVFTables)
				{			
					Trace("%08X %03d [Unknown]\n", tVftableInfo.eaStart, tVftableInfo.uMethods);
					AddTableEntry(ICON_UNKNOWN, tVftableInfo.eaStart, tVftableInfo.uMethods, "[Unknown]");
					return(TRUE);
				}
			}
			
			// See, above reaRdataLoc
			return(FALSE);
		}
	}

	// Point to next address
	reaRdataLoc += sizeof(UINT);	
	return(FALSE);
}

// Print out end stats
static void ShowEndStats()
{
	Output(" \n");	                	
	Output("==== Stats ====\n");	
	Output("RTTI:  %u\n", uRTTI_VFTables);
	Output("RTCI:  %u\n", uRTCI_VFTables);
	Output("Named: %u\n", uNamed_VFTables);
	Output("Other: %u\n", uOther_VFTables);	
	Output("Total vftables: %u\n", (uRTTI_VFTables + uRTCI_VFTables + uNamed_VFTables + uOther_VFTables));
	Output("-\n");
	Output("Functions recovered: %u\n", (get_func_qty() - uStartingFunctions));
	Output("Processing time: %s.\n", TimeString(GetTimeStamp() - s_StartTime));		
}

// Get a nice line of disassembled code text sans color tags
LPCTSTR GetDisasmText(ea_t ea)
{
    static char szBuff[MAXSTR];
    szBuff[0] = szBuff[MAXSTR - 1] = 0;

    if(generate_disasm_line(ea, szBuff, (sizeof(szBuff) - 1)))
		tag_remove(szBuff, szBuff, (sizeof(szBuff) - 1));

    return(szBuff);
}


// Get a pretty delta time string for output
static LPCTSTR TimeString(TIMESTAMP Time)
{
    static char szBuff[64];
    ZeroMemory(szBuff, sizeof(szBuff));

    if(Time >= HOUR)  
        _snprintf(szBuff, (sizeof(szBuff) - 1), "%.2f hours", (Time / (TIMESTAMP) HOUR));    
    else
    if(Time >= MINUTE)    
        _snprintf(szBuff, (sizeof(szBuff) - 1), "%.2f minutes", (Time / (TIMESTAMP) MINUTE));    
    else
        _snprintf(szBuff, (sizeof(szBuff) - 1), "%.2f seconds", Time);    

    return(szBuff);
}

// Output to IDA log window, and optionally to file and, or, debug channel output
void Output(LPCSTR format, ...)
{
	if(format)
	{
		// Format string
		va_list vl;
		char	szBuffer[2048];
		va_start(vl, format);
		_vsnprintf(szBuffer, SIZESTR(szBuffer), format, vl);
		szBuffer[SIZESTR(szBuffer)] = 0;	
		va_end(vl);

		// Out put it to IDA
		msg("%s", szBuffer);
		
		if(bDebugOutput)
			OutputDebugString(szBuffer);		

		// Write it log file
		if(hLogFile)
			qfwrite(hLogFile, szBuffer, strlen(szBuffer));
	}
}

// Return TRUE if address as a anterior comment
BOOL HasAnteriorComment(ea_t ea)
{
	// TODO: Is it possible for "extra lines" that are other then comments?	
	return(hasExtra(getFlags(ea)));
}

// Delete any anterior comment(s) at address if there is some
void KillAnteriorComments(ea_t ea)
{
	int nextAnterior = ExtraFree(ea, E_PREV);	
	while(nextAnterior > E_PREV)
	{
		ExtraDel(ea, E_PREV);		
		nextAnterior = ExtraFree(ea, E_PREV);
	};	
}

// Force a memory location to be DWORD size
void FixDWORD(ea_t eaAddress)
{
	SetUnknown(eaAddress, 4);
	doDwrd(eaAddress, sizeof(DWORD));
}

// Undecorate a class name minimal
LPSTR GetPlainClassName(IN LPSTR pszMangled, OUT LPSTR pszOutput)
{	
	pszOutput[0] = pszOutput[MAXSTR-1] = 0;
	demangle_name(pszOutput, (MAXSTR-1), pszMangled, MNG_NODEFINIT);	

	if(LPSTR pszEnding = strstr(pszOutput, "::`vftable'")) 
		*pszEnding = 0;

	return(pszOutput);
}


// Wrapper function for add_struc_member with nice error msgs
// See to make more sense of types: http://idapython.googlecode.com/svn-history/r116/trunk/python/idc.py
int AddStrucMember(struc_t *sptr, char *name, ea_t offset, flags_t flag, typeinfo_t *type, asize_t nbytes)
{
	int ret = add_struc_member(sptr, name, offset, flag, type, nbytes);
	switch(ret)
	{
		case STRUC_ERROR_MEMBER_NAME: 
		msg("AddStrucMember(): error: already has member with this name (bad name)\n");
		break;

		case STRUC_ERROR_MEMBER_OFFSET: 
		msg("AddStrucMember(): error: already has member at this offset\n");
		break;

		case STRUC_ERROR_MEMBER_SIZE: 
		msg("AddStrucMember(): error: bad number of bytes or bad sizeof(type)\n");
		break;

		case STRUC_ERROR_MEMBER_TINFO: 
		msg("AddStrucMember(): error: bad typeid parameter\n");
		break;

		case STRUC_ERROR_MEMBER_STRUCT: 
		msg("AddStrucMember(): error: bad struct id (the 1st argument)\n");
		break;

		case STRUC_ERROR_MEMBER_UNIVAR: 
		msg("AddStrucMember(): error: unions can't have variable sized members\n");
		break;

		case STRUC_ERROR_MEMBER_VARLAST: 
		msg("AddStrucMember(): error: variable sized member should be the last member in the structure\n");
		break;

		case STRUC_ERROR_MEMBER_NESTED: 
		msg("AddStrucMember(): error: recursive structure nesting is forbidden\n");
		break;
	};

	return ret;
}

// Set a range of bytes as unknown since IDA API do_unknown_range() is prone to fail
// and occasionally leads to a run on condition.
// Note: An IDA 5.x issue, could be fixed now
void SetUnknown(ea_t ea, asize_t size)
{
// 1.05 causes more problems then it fixes
// The do_unknown() size overrun problem overwrites some changes
	
	ea_t Ptr = ea; 
	ea_t End = (ea + size);
	while(Ptr < End) do_unknown(Ptr++, DOUNK_SIMPLE);
	
	//auto_mark_range(ea, End, AU_UNK);

}
