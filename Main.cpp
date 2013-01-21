
// ****************************************************************************
// File: Main.cpp
// Desc: Plug-in main
//
// ****************************************************************************
#include "stdafx.h"

// === Function Prototypes ===
int IDAP_init();
void IDAP_term();
void IDAP_run(int arg);
extern void CORE_Init();
extern void CORE_Process(int iArg);
extern void CORE_Exit();

// === Data ===
static char IDAP_comment[] = "Class Informer: Builds C++ class type info, member functions, etc.";
static char IDAP_help[]	   = "Class Informer: Use hotkey to activate..";
static char IDAP_name[]    = "Class Informer";
static char IDAP_hotkey[]  = "Alt-3"; // Default hotkey

// Plug-in description block
extern "C" ALIGN(16) plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,	// IDA version plug-in is written for	
	0, /*PLUGIN_UNL,*/      // Plug-in flags	
	IDAP_init,	            // Initialization function
	IDAP_term,	            // Clean-up function
	IDAP_run,	            // Main plug-in body
	IDAP_comment,	        // Comment
	IDAP_help,	            // As above
	IDAP_name,	            // Plug-in name shown in Edit->Plugins menu
	IDAP_hotkey	            // Hot key to run the plug-in
};

// Init
int IDAP_init()
{	
	if((strncmp(inf.procName, "metapc", 8) == 0) && (ph.id == PLFM_386) && (inf.filetype != f_ELF))
	{		
		CORE_Init();
		return(PLUGIN_KEEP);
	}

	msg("\n* Class Informer: Plug-in not loading. Not recognized as a PE binary format, x86, 32bit target *\n\n");
	return(PLUGIN_SKIP);     
}

// Un-init
void IDAP_term()
{
    CORE_Exit();
}

// Run 
void IDAP_run(int iArg)
{ 
	CORE_Process(iArg);
}
