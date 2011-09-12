#include <arpa/inet.h>
#include <stdlib.h>
#include "common.h"
#include "parser.h"
#include "ldlua.h"

LDLUA_METHOD pkb_index(lua_State* L);
LDLUA_METHOD pkb_range(lua_State* L);
LDLUA_METHOD pkb_len(lua_State* L);
LDLUA_METHOD pkb_gc(lua_State *L);
//LDLUA_METHOD pkb_tostring(lua_State *);
LDLUA_METHOD pkbrange_uint(lua_State* L);
LDLUA_METHOD pkbrange_gc(lua_State *L);
LDLUA_CLASS_DEFINE(pkb,FAIL_ON_NULL("expired pkb"),NOP);
LDLUA_CLASS_DEFINE(pkbrange,FAIL_ON_NULL("expired pkbrange"),NOP);

static const luaL_reg pkb_methods[] = {
    {"range", pkb_range},
    {"len", pkb_len},
	{"getbyte", pkb_index},
    { NULL, NULL },
};

static const luaL_reg pkb_meta[] = {
    {"__call", pkb_range},
//    {"__tostring", pkb_tostring},
    {"__gc", pkb_gc},
    { NULL, NULL },
};

static const luaL_reg pkbrange_methods[] = {
	{"uint", pkbrange_uint},
	{NULL, NULL},
};
static const luaL_reg pkbrange_meta[] = {
	{"__gc", pkbrange_gc},
    { NULL, NULL },
};

static inline uint32_t __app_length(pkb pkt)
{
	return pkt->real_applen;
}

static inline int __handle_offset(int offset, int length, uint32_t app_len)
{
	if (offset < 0) {
		offset = app_len + offset;
	}
	
	if ((offset < 0) || (length < 0) || (offset + length > (int)app_len)) {
        return -1;
	} else {
		return offset;
	}
}


static pkbrange new_pkbrange(lua_State* L, pkb pkt, int offset, int length) 
{
	pkbrange pkbr;
	uint32_t app_len = __app_length(pkt);

	offset = __handle_offset(offset, length, app_len);
	if (offset < 0) {
		luaL_error(L,"Range is out of bounds\n");
		return NULL;
	}

	pkbr = malloc(sizeof(struct pkbrange_s));
	if (pkbr == NULL) {
		return NULL;
	} else {
		pkbr->pkt = pkt;
		pkbr->offset = offset;
		pkbr->length = length;
	}
	return pkbr;
}

pkb* push_pkb_to_stack(lua_State* L, pkb pkt) {
    return push_pkb(L, pkt);
}

LDLUA_METHOD pkb_index(lua_State* L)
{
#define LDLUA_OPTARG_PKB_INDEX 2 /* The index (in octets) from the begining of the pkb. Defaults to 0. */
	pkb pkt = check_pkb(L,1);
    int index = luaL_optint(L,LDLUA_OPTARG_PKB_INDEX,0);
	uint8_t *app_data;
	index = __handle_offset(index, 1, __app_length(pkt));
	if (index < 0) {
		luaL_error(L,"Range is out of bounds\n");
		return 0;
	}
	app_data = (uint8_t *)(pkt->data + pkt->app_offset + index);
	lua_pushnumber(L, *app_data);
	return 1;
}

LDLUA_METHOD pkb_range(lua_State* L) 
{
	/* Creates a pkbr from this pkb. This is used also as the pkb:__call() metamethod. */
#define LDLUA_OPTARG_PKB_RANGE_OFFSET 2 /* The offset (in octets) from the begining of the pkb. Defaults to 0. */
#define LDLUA_OPTARG_PKB_RANGE_LENGTH 3 /* The length (in octets) of the range. Defaults to until the end of the pkb. */

    pkb pkt = check_pkb(L,1);
    int offset = luaL_optint(L,LDLUA_OPTARG_PKB_RANGE_OFFSET,0);
    int len = luaL_optint(L,LDLUA_OPTARG_PKB_RANGE_LENGTH,-1);
    pkbrange pkbr;

    if (!pkt) return 0;

    if ((pkbr = new_pkbrange(L, pkt, offset,len))) {
        push_pkbrange(L,pkbr);
		LDLUA_RETURN(1); /* The pkbRange */
    }

    return 0;
}

LDLUA_METHOD pkb_len(lua_State* L) 
{
	/* Obtain the length of a TVB */
    pkb pkt = check_pkb(L,1);

    if (!pkt) {
		return 0;
	}
    lua_pushnumber(L, __app_length(pkt));
    LDLUA_RETURN(1); /* The length of the pkt. */
}

LDLUA_METHOD pkb_gc(lua_State *L)
{
	return 0;
}

LDLUA_METHOD pkbrange_uint(lua_State* L)
{
	pkbrange pkbr = check_pkbrange(L, 1);
	pkb packet;
	int offset;
	void *app_data;
	if (!(pkbr && pkbr->pkt)) {
		return 0;
	}

	packet = pkbr->pkt;
	offset = pkbr->offset;
	app_data = packet->data + packet->app_offset;
	switch (pkbr->length) 
	{
	case 1:
		lua_pushnumber(L, *(uint8_t *)(app_data + offset));
		return 1;
	case 2:
		lua_pushnumber(L, htons(*(uint16_t *)(app_data + offset)));
		return 1;
	case 4:
		lua_pushnumber(L, htonl(*(uint32_t *)(app_data + offset)));
		return 1;
	default:
		luaL_error(L, "pkbrange:get_uint() does not handle %d byte integers\n", pkbr->length);
		return 0;
	}
	return 0;
}

LDLUA_METHOD pkbrange_gc(lua_State *L)
{
	pkbrange tvb = check_pkbrange(L,1);
	free(tvb);
	return 0;
}

int pkb_register(lua_State* L) 
{
	LDLUA_REGISTER_CLASS(pkb);
    return 1;
}

int pkbrange_register(lua_State* L) 
{
	LDLUA_REGISTER_CLASS(pkbrange);
    return 1;
}
