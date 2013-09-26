// Get or create an IDA struct
#define ADD_STRUCT(ID, NAME, COMMENT)\
{\
	ptStruct = NULL;\
	ID = get_struc_id(NAME);\
	if(ID == BADADDR)\
		ID = add_struc(BADADDR, NAME);\
	if(ID != BADADDR)\
		ptStruct = get_struc(ID);\
	if(ptStruct)\
	{\
		del_struc_members(ptStruct, 0, MAXADDR);\
		set_struc_cmt(ID, COMMENT, true);\
	}\
	else\
	msg(" ** \"" NAME "\" create failed! **\n");\
}

// Add structure member macro
#define ADD_MEMBER(pSTRUCT, FLAG, MT, TYPE, MEMBER)\
{\
	if(add_struc_member(pSTRUCT, #MEMBER, offsetof(TYPE, MEMBER), FLAG, MT, sizeof(((TYPE*)0)->MEMBER)) != 0)\
		msg(" ** ADD_MEMBER(): %s failed! %d, %d **\n", #MEMBER, offsetof(TYPE, MEMBER), sizeof(((TYPE*)0)->MEMBER));\
}