
// ****************************************************************************
// File: SegmentSelectBox.cpp 
// Desc: Multi-select DB segment box
//
// ****************************************************************************
#include <stdafx.h>
#include <IDACustomCommon.h>
#include <SegmentSelectBox.h>

#pragma comment(lib, "Comctl32.lib")

// Choose box text column widths
ALIGN(16) static const int aWidth[] = {9, 9, 9, 9, 5, 4};

// Local info container
struct tBOXINFO
{
    tBOXINFO(SEGBOX::eSGST _ePeref) : hWndListBox(NULL) { eSuggest = _ePeref; };

	SEGBOX::SEGLIST cSegList;   
	HWND            hWndListBox;
	SEGBOX::eSGST   eSuggest;
};

// Find non-QT list box HWND
static BOOL CALLBACK FindListCtrlProc(HWND hWnd, LPARAM lParam)
{
	char szClass[sizeof("XPListView") + 1]; szClass[0] = 0;
	if(GetClassName(hWnd, szClass, sizeof(szClass)))
	{
		// Button?
        // *** No longer works since IDA 6.x, at least not on Windows 7 ***
		if(qstrcmp(szClass, "TButton") == 0)
		{
			char szName[sizeof("Search") + 1];
			if(GetWindowText(hWnd, szName, sizeof(szName)) > 1)
			{
				if(qstrcmp(szName, "Search") == 0)									
					ShowWindow(hWnd, SW_HIDE);
				else
				if(qstrcmp(szName, "Help") == 0)									
					ShowWindow(hWnd, SW_HIDE);
			}
		}
		else
		// ListView control?
		if(qstrcmp(szClass, "XPListView") == 0)
		{	
			// The header must be disabled to turn off the sort feature
			EnableWindow(ListView_GetHeader(hWnd), 0);

			// Save the handle
			*((HWND *) lParam) = hWnd;			
		}
	}

	return(TRUE);
}
//
static BOOL CALLBACK GetChooseListBoxProc(HWND hWnd, LPARAM lParam)
{				
	char szClass[sizeof("TChooser") + 1]; szClass[0] = 0;
	if(GetClassName(hWnd, szClass, sizeof(szClass)))
	{
		if(qstrcmp(szClass, "TChooser") == 0)
		{		
		    // Process controls
		    EnumChildWindows(hWnd, FindListCtrlProc, lParam);
		    if(*((PUINT) lParam) > 0)
            {
                // Remove the min and maximize bars                    
                SetWindowLong(hWnd, GWL_STYLE, (GetWindowLong(hWnd, GWL_STYLE) & ~(WS_MINIMIZEBOX | WS_MAXIMIZEBOX)));
		        return(FALSE);           
            }
		}
	}

	return(TRUE);
}	
//
static HWND GetListViewCtrl()
{	
	HWND hWnd = NULL;
	EnumThreadWindows(GetCurrentThreadId(), GetChooseListBoxProc, (LPARAM) &hWnd);
	return(hWnd);
}


// Get row count
static ulong idaapi SegBoxSizerCB(PVOID obj){ return(get_segm_qty()); }

// Subclass (non-QT) ListView box to allow us to set multiple segments
static LRESULT CALLBACK ListViewSubClass(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	switch(uMsg)
	{		
		case WM_DESTROY:
		{   
		    // Get selected rows now that we are exiting
			if(ListView_GetSelectedCount(hWnd))
			{             
				int iRows = ListView_GetItemCount(hWnd);         
				for(int i = 0; i < iRows; i++)
				{
					if(ListView_GetItemState(hWnd, i, LVIS_SELECTED))					
						((tBOXINFO *) dwRefData)->cSegList.push_front(getnseg(i));					
				}
			}

			BOOL bResult = RemoveWindowSubclass(hWnd, ListViewSubClass, 8);
			_ASSERT(bResult);
		}
		break;
	};

	return(DefSubclassProc(hWnd, uMsg, wParam, lParam));
}

// Get header, or line text
static void idaapi SegBoxGetLineCB(PVOID pParm, ulong n, char* const *cell)
{
	// Header
	if(n == 0)
	{
		static const char *aszHeader[] = {"Name", "Start", "End", "Size", "Class", "Flags"};
		for(int i = 0; i < 6; i++)
			strcpy(cell[i], aszHeader[i]);
	}
	// Line
	else
	{			
		tBOXINFO *ptBoxInfo = (tBOXINFO *) pParm;

        // Subclass ListView control (non-QT version only)
		if(!IDACSTM::IsQtVersion() && !ptBoxInfo->hWndListBox) 
		{       
	        if(ptBoxInfo->hWndListBox = GetListViewCtrl())               
			    SetWindowSubclass(ptBoxInfo->hWndListBox, ListViewSubClass, 8, (DWORD_PTR) ptBoxInfo);         
		}

		if(segment_t *ptSeg = getnseg(n - 1))
		{
			// Segment name
			char szName[64];
			if(get_true_segm_name(ptSeg, szName, (SIZESTR(szName) - 4)) <= 0)					
				qprintf(szName, ".unknown%d", (n - 1));			

			// Optionally show suggestions for code, or data
			switch(ptBoxInfo->eSuggest)
			{
				case SEGBOX::eSGST_CODE:
				{
					// If executable flag is set
					if(ptSeg->perm & SEGPERM_EXEC)
						qstrncat(szName, " *", SIZESTR(szName));
				}
				break;

				case SEGBOX::eSGST_DATA:
				{
					// Not executable
					if(!(ptSeg->perm & SEGPERM_EXEC))
					{
						if(!strstr(szName, "idata") && (strstr(szName, "data") || strstr(szName, "DATA")))
							qstrncat(szName, " *", SIZESTR(szName));
					}
				}
				break;
			};
			qsnprintf(cell[0], aWidth[0], "%s", szName);

			// Extents
			qsnprintf(cell[1], aWidth[1], "%08X", ptSeg->startEA);
			qsnprintf(cell[2], aWidth[2], "%08X", ptSeg->endEA);
			qsnprintf(cell[3], aWidth[3], "%08X", ptSeg->size());

			// Segment class name
			char szClass[16];
			if(get_segm_class(ptSeg, szClass, SIZESTR(szClass)) <= 0)
				qstrncpy(szClass, "none", sizeof("none"));
			qsnprintf(cell[4], aWidth[4], "%s", szClass);

			// Permission flags
			char szFlags[4] = {"..."};
			if(ptSeg->perm & SEGPERM_READ)
				szFlags[0] = 'R';
			if(ptSeg->perm & SEGPERM_WRITE)
				szFlags[1] = 'W';
			if(ptSeg->perm & SEGPERM_EXEC)
				szFlags[2] = 'E';					
			qsnprintf(cell[5], aWidth[5], "%s", szFlags);			
		}
		else
			msg("** Failed to get info for for segment %d! ***\n", (n - 1));
	}
}

static int CALLBACK SegBoxGetIconCB(PVOID pObj, UINT n)
{
	//return(n); // With list of 160+ to view all available icons
	if(n == 0)
		return(0);
	else
		return(46);
}

// Select segment(s) for QT version
static UINT idaapi SelectCB(void *obj, UINT n)
{
    if(IS_START_SEL(n) || IS_EMPTY_SEL(n))    
        ((tBOXINFO *) obj)->cSegList.clear();    
    else
    if(IS_SEL(n))          
        ((tBOXINFO *) obj)->cSegList.push_back(getnseg(n - 1));   

    return(1);
}

// Select one or more segments
SEGBOX::SEGLIST SEGBOX::Select(LPCSTR pszLable, eSGST ePeref)
{
	tBOXINFO tBoxInfo(ePeref);

    // Nix status bar
    qstring cTitle(CHOOSER_NOSTATUSBAR); cTitle += pszLable;

    // From "Delete" to "Select" for hacked QT multi-select
    const char * const aPopUpNames[] = {"1", "Select", "3", "4"};

    UINT uSelected = choose2((CH_MODAL | CH_MULTI | CH_MULTI), 
	-1,-1,-1,-1,
	&tBoxInfo, 6, aWidth, SegBoxSizerCB, SegBoxGetLineCB, cTitle.c_str(),
	-1,				    // icon
	0,				    // start line
    (IDACSTM::IsQtVersion() ? SelectCB : NULL),	// "kill" callback
	NULL,			    // "new" callback
	NULL,		        // "update" callback
	NULL,			    // "edit" callback
	NULL,               // function to call when the user pressed Enter
	NULL,		        // function to call when the window is closed
	aPopUpNames,		// use default popup menu items
	SegBoxGetIconCB);	// use the same icon for all lines

    // Single select case?
    if((uSelected > 0) && tBoxInfo.cSegList.empty())    
        tBoxInfo.cSegList.push_back(getnseg(uSelected - (IDACSTM::IsQtVersion() ? 1 : 0)));    

    // Show selected segments
    if(!tBoxInfo.cSegList.empty())
    {
        msg("Segment%s selected: ", ((tBoxInfo.cSegList.size() == 1) ? "" : "s"));
        UINT uIndex = 0;
        for(SEGLIST::iterator i = tBoxInfo.cSegList.begin(); i != tBoxInfo.cSegList.end();)
        {           
            char szName[64];
            if(get_true_segm_name(*i, szName, (SIZESTR(szName) - 4)) <= 0)					
                qprintf(szName, ".unknown%d", uIndex++);			

            if(++i != tBoxInfo.cSegList.end())
                msg("\"%s\", ", szName);
            else
                msg("\"%s\".", szName);
        }        
        msg("\n");
    }

	return(tBoxInfo.cSegList);
} 