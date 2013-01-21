
// ****************************************************************************
// File: SegmentSelectBox.h
// Desc: Multi-select DB segment box
//
// ****************************************************************************
#pragma once

namespace SEGBOX
{
	// Optional suggested segment types, but a start next to them
	enum eSGST
	{
		eSGST_NONE,
		eSGST_CODE,
		eSGST_DATA,
	};

	typedef qlist<segment_t *> SEGLIST;

	SEGLIST Select(LPCSTR pszLable = "Choose segment(s)", eSGST eSuggest = eSGST_NONE);
};
