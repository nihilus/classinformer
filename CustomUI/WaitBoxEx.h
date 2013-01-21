
// ****************************************************************************
// File: WaitBoxEx.h
// Desc: Custom wait box handler
//
// ****************************************************************************
#pragma once

// Include IDA headers before me..
#include <IDACustomCommon.h>

class cWaitBoxEx
{
public:
	cWaitBoxEx() : m_hWndProgress(NULL)
	{
		s_bIsQtVer = IDACSTM::IsQtVersion();
		s_hMsgHook = NULL;
	};

	static HHOOK s_hMsgHook;
	static HWND  s_hWndWaitBox;
	static HWND  s_hWndCancel;	
	static BOOL  s_bInputBreak;
	static BOOL  s_bIsQtVer;
	static BOOL  s_bStarted;

	// Show wait box
	void Begin(const char *format, ...)
	{
		m_hWndProgress = s_hWndWaitBox = s_hWndCancel = NULL;
		s_bInputBreak = FALSE;

		// Put up IDA wait box
		va_list va;
		va_start(va, format);
		show_wait_box_v(format, va);
		va_end(va);

		// Get wait box handle
		{
			Sleep(2);
			WaitForInputIdle(GetCurrentProcess(), 2000);

			int iRetries = 256;
			while(!s_hWndWaitBox && iRetries--)
			{
				FindWaitBox();
				if(!s_hWndWaitBox) Sleep(2);
			};
		}

		// Add a progress bar to it
		if(s_hWndWaitBox)
		{
			//msg("Wait win: %08X %d\n", s_hWndWaitBox, s_bIsQt);
			if(!s_bIsQtVer)
			{
				const UINT BARWIDTH = 230;
				if(m_hWndProgress = CreateWindowEx(0, PROGRESS_CLASS, "", (WS_VISIBLE | WS_BORDER | WS_CHILD), ((283-BARWIDTH)/2)-2,20, BARWIDTH,17, s_hWndWaitBox, NULL, NULL, NULL))
				{
					SendMessage(m_hWndProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

					#define GRAY(x) RGB(x,x,x)
					SendMessage(m_hWndProgress, PBM_SETBKCOLOR,  0, (LPARAM) GRAY(78));
					SendMessage(m_hWndProgress, PBM_SETBARCOLOR, 0, (LPARAM) RGB(100,210,0));
					SendMessage(m_hWndProgress, PBM_SETPOS, (WPARAM) 0, 0);

					m_LastAnimTime = GetTimeStampLow();
					m_iAnimStep = 0;
				}

				// Get cancel button HWND if it's up
				s_hWndCancel = FindCancelButton();
			}

			// Hook to receive key and mouse inputs
			s_hMsgHook = SetWindowsHookEx(WH_CALLWNDPROCRET, GetMsgProc, NULL, GetCurrentThreadId());
		}

		clearBreak();
		s_bStarted = TRUE;
	}

	// End wait box
	void End()
	{
		// Remove hook
		if(s_hMsgHook)
		{
			UnhookWindowsHookEx(s_hMsgHook);
			s_hMsgHook = NULL;
		}

		// Remove progress bar
		if(m_hWndProgress)
		{
			SendMessageA(m_hWndProgress, WM_CLOSE, 0,0);
			m_hWndProgress = NULL;
		}

		// Restore default text
		if(s_hWndWaitBox)
		{
			SetWindowTextA(s_hWndWaitBox, "Please wait...");			
			s_hWndWaitBox = NULL;
		}

		callui(ui_mbox, mbox_hide, NULL, &callui);
		s_hWndWaitBox = m_hWndProgress = NULL;
		s_bStarted = FALSE;
	}

	// Return TRUE if break pressed or cancel button clicked
	BOOL IsBreak()
	{
		return(s_bInputBreak || wasBreak());
	}

	// Return TRUE if break pressed, or cancel clicked, show progress on window text
	BOOL IsBreakProgress(int iPercent)
	{
		if(s_bStarted)
		{	
			if(iPercent < 0) iPercent = 0;
			else
			if(iPercent > 100) iPercent = 100;

			static const char aCharAnim[] = {"/--\\|"};
			TIMESTAMP Time = GetTimeStampLow();
			if((Time - m_LastAnimTime) > 0.250)
			{
				m_LastAnimTime = Time;
				if(++m_iAnimStep >= SIZESTR(aCharAnim)) m_iAnimStep = 0;
			}

			// Set window text
			char szBuffer[256]; szBuffer[SIZESTR(szBuffer)] = 0;
			qsnprintf(szBuffer, SIZESTR(szBuffer), " Please wait... %d%%  %c", iPercent, aCharAnim[m_iAnimStep]);
			SetWindowTextA(s_hWndWaitBox, szBuffer);			

			// Set progress bar position
			if(m_hWndProgress)
				SendMessage(m_hWndProgress, PBM_SETPOS, (WPARAM) iPercent, 0);			

			return(s_bInputBreak || wasBreak());
		}
		else
			return(TRUE);
	}

	BOOL IsBreakProgress(int iPercent, LPCSTR pszSegnemnt)
	{
		if(s_bStarted)
		{		
			if(iPercent < 0) iPercent = 0;
			else
			if(iPercent > 100) iPercent = 100;

			static const char aCharAnim[] = {"/--\\|"};
			TIMESTAMP Time = GetTimeStampLow();
			if((Time - m_LastAnimTime) > 0.250)
			{
				m_LastAnimTime = Time;
				if(++m_iAnimStep >= SIZESTR(aCharAnim)) m_iAnimStep = 0;
			}

			// Set window text
			char szBuffer[256]; szBuffer[SIZESTR(szBuffer)] = 0;
			qsnprintf(szBuffer, SIZESTR(szBuffer), " Searching \"%s\"..  %d%%  %c", pszSegnemnt, iPercent, aCharAnim[m_iAnimStep]);
			SetWindowTextA(s_hWndWaitBox, szBuffer);			

			// Set progress bar position
			if(m_hWndProgress)
				SendMessage(m_hWndProgress, PBM_SETPOS, (WPARAM) iPercent, 0);			

			return(s_bInputBreak || wasBreak());
		}
		else
			return(TRUE);
	}

	BOOL IsQtQUI(){ return(s_bIsQtVer); }

private:	
    TIMESTAMP m_LastAnimTime;
	HWND m_hWndProgress;	
	int  m_iAnimStep;

	// Find IDA's wait box
	void FindWaitBox()
	{
		s_hWndWaitBox = NULL;		
        EnumThreadWindows(GetCurrentThreadId(), FindWaitBoxProc, (LPARAM) &s_hWndWaitBox);        
	}
	//
    static BOOL CALLBACK FindWaitBoxProc(HWND hWnd, LPARAM lParam)
    {
        char szClass[16];
        if(GetClassName(hWnd, szClass, sizeof(szClass)))
        {
            if(s_bIsQtVer)
            {
                if(qstrcmp(szClass, "QWidget") == 0)
                {               
                    if(GetWindowLong(hWnd, GWL_STYLE) == 0x16CC0000)
                    {                       
                        *((HWND *) lParam) = hWnd;
                        return(FALSE);                           
                    }                    
                }
            }
            else
            {
                if(qstrcmp(szClass, "TWaitForm") == 0)
                {                 
                    *((HWND *) lParam) = hWnd;
                    return(FALSE);                  
                }
            }
        }

        return(TRUE);
    }

	// Find wait box cancel button if it has one
	HWND FindCancelButton()
	{
		HWND hWndCancel = NULL;

		if(s_hWndWaitBox)
			EnumChildWindows(s_hWndWaitBox, FindCancelButtonProc, (LPARAM) &hWndCancel);

		return(hWndCancel);
	}
	//
	static BOOL CALLBACK FindCancelButtonProc(HWND hWnd, LPARAM lParam)
	{
		char szClass[sizeof("TButton") + 1];
		if(GetClassName(hWnd, szClass, sizeof(szClass)))
		{
			if(qstrcmp(szClass, "TButton") == 0)
			{
				*((HWND *) lParam) = hWnd;
				return(FALSE);
			}
		}

		return(TRUE);
	}

	// Dialog hook to catch cancel button click
	static LRESULT CALLBACK GetMsgProc(int nCode, WPARAM wParam, LPARAM lParam)
	{
		if(nCode == HC_ACTION)
		{
			PCWPRETSTRUCT pInfo = (PCWPRETSTRUCT) lParam;
			HWND hWnd = pInfo->hwnd;

			switch(pInfo->message)
			{				
				case WM_SHOWWINDOW:
				{
					//msg("WM_SHOWWINDOW wait\n");
				}
				break;

				case WM_LBUTTONDOWN:
				if(s_hWndCancel && (hWnd == s_hWndCancel))
				{
					s_bInputBreak = TRUE;
				}
				break;

				case WM_KEYDOWN:
				{
					if(hWnd == s_hWndWaitBox)
					{
						if(pInfo->wParam == VK_PAUSE)
							s_bInputBreak = TRUE;
					}
					else
					if(s_hWndCancel && (hWnd == s_hWndCancel))
					{
						if((pInfo->wParam == VK_PAUSE) || (pInfo->wParam == VK_SPACE))
							s_bInputBreak = TRUE;
					}
				}
				break;

				// Handle color messages test
				#if 0
				case WM_CTLCOLORMSGBOX:
				case WM_CTLCOLORDLG:
				case WM_CTLCOLORSCROLLBAR:
				case WM_CTLCOLORBTN:
				case WM_CTLCOLORSTATIC:
				case WM_CTLCOLOREDIT:
				case WM_CTLCOLORLISTBOX:
				{
					//msg("Color msg %X, UD: %X\n", pInfo->message, GetWindowLongPtr(pInfo->hwnd, GWLP_USERDATA));


					//static int iStep = 0;
					//printf("HWND: %04X, C: %04X, P: %08X, %d\n", lParam, uMsg, GetWinDat((HWND) lParam), iStep++);
					//PrintClassName(hWnd);
					//PrintClassName((HWND) lParam);

					// Get window's data block and handle custom colors
					/*
					if(tCWINDAT *ptWinDat = GetWinDat((HWND) lParam))
					{
						if(ptWinDat->Foreground != CLR_INVALID)
							SetTextColor((HDC) wParam, ptWinDat->Foreground);

						if(ptWinDat->hBackground)
						{
							SetBkColor((HDC) wParam, ptWinDat->Background);
							return((LPARAM) ptWinDat->hBackground);
						}
					}
					*/

					/*
					COLORREF Foreground;
					COLORREF Background;
					HBRUSH   hBackground;
					SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR) pcWinDat);
					pcWinDat->hBackground = CreateSolidBrush(pcWinDat->Background);
					*/
				}
				break;
				#endif
			};

			//Trace(" M: %04X, H: %08X\n", LOWORD(pwp->message), pwp->hwnd);
		}

		return(::CallNextHookEx(s_hMsgHook, nCode, wParam, lParam));
	}
};

HHOOK cWaitBoxEx::s_hMsgHook    = NULL;
HWND  cWaitBoxEx::s_hWndWaitBox = NULL;
HWND  cWaitBoxEx::s_hWndCancel  = NULL;
BOOL  cWaitBoxEx::s_bInputBreak = FALSE;
BOOL  cWaitBoxEx::s_bIsQtVer	= FALSE;
BOOL  cWaitBoxEx::s_bStarted	= FALSE;
