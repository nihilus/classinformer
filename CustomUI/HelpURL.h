
// ****************************************************************************
// File: HelpURL.h
// Desc: Hijack the dialog "Small help" window to put my URL on it
//
// ****************************************************************************
#pragma once

// Include IDA headers before me..
#include <IDACustomCommon.h>

class cURLHelp
{
public:
	cURLHelp(LPCSTR pcszURL)
	{
		s_pcszURL   = pcszURL;
		s_bShowOnce = TRUE;
		s_bIsQtVer  = IDACSTM::IsQtVersion();

		// Hook to catch help window in focus (non-QT version)
		if(!s_bIsQtVer)
			s_hMsgHook = SetWindowsHookEx(WH_CALLWNDPROCRET, MsgHookProc1, NULL, GetCurrentThreadId());
	};

	~cURLHelp()
	{
		if(s_hMsgHook)     UnhookWindowsHookEx(s_hMsgHook);
		if(s_hWndMyButton) DestroyWindow(s_hWndMyButton);

		// Don't NULL help button, it might be cached
		s_hMsgHook     = NULL;
		s_hWndMyButton = NULL;
	};

	// Open browser to URL
	static void OpenSupportForum() { open_url(s_pcszURL); }

private:
	static HHOOK  s_hMsgHook;
	static HWND   s_hWndMyButton;
	static LPCSTR s_pcszURL;
	static BOOL   s_bIsQtVer;
	static BOOL   s_bShowOnce;

	// Hook to catch the plug-in dialog creation
	static LRESULT CALLBACK MsgHookProc1(int nCode, WPARAM wParam, LPARAM lParam)
	{
		if(nCode == HC_ACTION)
		{
			LPCWPRETSTRUCT pInfo = (LPCWPRETSTRUCT) lParam;
			switch(pInfo->message)
			{
				case WM_SHOWWINDOW:
				{
					char szClass[sizeof("TDynHelpForm") + 1]; szClass[0] = szClass[SIZESTR(szClass)] = 0;
					if(GetClassNameA(pInfo->hwnd, szClass, SIZESTR(szClass)))
					{
						if(strcmp(szClass, "TDynHelpForm") == 0)
						{
							char szName[sizeof("Small help") + 1]; szName[0] = szName[SIZESTR(szName)] = 0;
							if(GetWindowTextA(pInfo->hwnd, szName, SIZESTR(szName)))
							{
								if(HWND hWndOkBtn = FindWindowExA(pInfo->hwnd, NULL, "TButton", "OK"))
								{
									// Unhook our self
									UnhookWindowsHookEx(s_hMsgHook);
									s_hMsgHook = NULL;

									RECT DlgRect;
									GetClientRect(pInfo->hwnd, &DlgRect);
									RECT BtnRect;
									GetClientRect(hWndOkBtn, &BtnRect);
									int iBtnH  = ((BtnRect.bottom - BtnRect.top) + 1);

									// Create my forum button
									if(s_hWndMyButton = CreateWindowExA(0, WC_BUTTON, "Support forum", (WS_VISIBLE | BS_PUSHBUTTON | WS_CHILD | BS_FLAT),
									(DlgRect.right - 129),(DlgRect.bottom  - (iBtnH + 5)), 122,(iBtnH - 5), pInfo->hwnd, NULL, NULL, NULL))
									{
										// Hook to catch my button press
										s_hMsgHook = SetWindowsHookEx(WH_CALLWNDPROCRET, MsgHookProc2, NULL, GetCurrentThreadId());
									}
									return(0);
								}
							}
						}
						else
						if(strcmp(szClass, "TMyDialog") == 0)
						{
							if(s_bShowOnce)
							{
								//msg("TMyDialog: %X\n", pInfo->hwnd);
								s_bShowOnce = FALSE;
                              
								// Change the appearance of the forum button
								if(HWND hWndForumBtn = FindWindowExA(pInfo->hwnd, NULL, "TButton", "Open support forum"))
								{
									SetWindowLong(hWndForumBtn, GWL_STYLE, (WS_VISIBLE | BS_PUSHBUTTON | WS_CHILD | BS_FLAT));

									RECT Rect;
									GetWindowRect(hWndForumBtn, &Rect);
									POINT Point = {Rect.left, Rect.top};
									ScreenToClient(pInfo->hwnd, &Point);
									SetWindowPos(hWndForumBtn, pInfo->hwnd, Point.x,(Point.y + 2), (Rect.right - Rect.left), ((Rect.bottom - Rect.top) - 6), (SWP_NOZORDER | SWP_NOREDRAW));
								}
							}
						}
					}
				}
				break;
			};
		}

		return(::CallNextHookEx(s_hMsgHook, nCode, wParam, lParam));
	}

	// Dialog hook to catch forum button click
	static LRESULT CALLBACK MsgHookProc2(int nCode, WPARAM wParam, LPARAM lParam)
	{
		if(nCode == HC_ACTION)
		{
			PCWPRETSTRUCT pInfo = (PCWPRETSTRUCT) lParam;
			if(pInfo->message == WM_COMMAND)
			{
				if((HWND) pInfo->lParam == s_hWndMyButton)
				{
					OpenSupportForum();
				}
			}
		}

		return(::CallNextHookEx(s_hMsgHook, nCode, wParam, lParam));
	}
};

HHOOK  cURLHelp::s_hMsgHook     = NULL;
HWND   cURLHelp::s_hWndMyButton = NULL;
BOOL   cURLHelp::s_bIsQtVer		= FALSE;
BOOL   cURLHelp::s_bShowOnce	= TRUE;
LPCSTR cURLHelp::s_pcszURL      = "";
