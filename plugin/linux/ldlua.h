#ifndef __LDLUA_H__
#define __LDLUA_H__

#include "lua.h"
#include "lauxlib.h"
#include "parser.h"

#define LDLUA_METHOD static int 
#define LDLUA_CONSTRUCTOR static int 
#define LDLUA_ATTR_SET static int 
#define LDLUA_ATTR_GET static int 
#define LDLUA_METAMETHOD static int
#define NOP
#define TRUE 1
#define FALSE 0

typedef packet_t * pkb;
typedef struct pkbrange_s * pkbrange;
typedef int gboolean;

struct pkbrange_s {
	pkb pkt;
	int offset;
	int length;
};

#define FAIL_ON_NULL(s) if (! *p) luaL_argerror(L,index,s)
#define LDLUA_RETURN(i) return (i);

#define LDLUA_CLASS_DEFINE(C,check_code,push_code) \
	C to_##C(lua_State* L, int index) { \
		C* v = (C*)lua_touserdata (L, index); \
		if (!v) luaL_typerror(L,index,#C); \
		return *v; \
	} \
	C check_##C(lua_State* L, int index) { \
		C* p; \
		luaL_checktype(L,index,LUA_TUSERDATA); \
		p = (C*)luaL_checkudata(L, index, #C); \
		check_code; \
		return p ? *p : NULL; \
	} \
	C* push_##C(lua_State* L, C v) { \
		C* p; \
		luaL_checkstack(L,2,"Unable to grow stack\n"); \
		p = lua_newuserdata(L,sizeof(C)); *p = v; \
		luaL_getmetatable(L, #C); lua_setmetatable(L, -2); \
		push_code; \
		return p; \
	}\
	gboolean is_##C(lua_State* L,int i) { \
		void *p; \
		if(!lua_isuserdata(L,i)) return FALSE; \
		p = lua_touserdata(L, i); \
		lua_getfield(L, LUA_REGISTRYINDEX, #C); \
		if (p == NULL || !lua_getmetatable(L, i) || !lua_rawequal(L, -1, -2)) p=NULL; \
		lua_pop(L, 2); \
		return p ? TRUE : FALSE; \
	} \
	C shift_##C(lua_State* L,int i) { \
		C* p; \
		if(!lua_isuserdata(L,i)) return NULL; \
		p = lua_touserdata(L, i); \
		lua_getfield(L, LUA_REGISTRYINDEX, #C); \
		if (p == NULL || !lua_getmetatable(L, i) || !lua_rawequal(L, -1, -2)) p=NULL; \
		lua_pop(L, 2); \
		if (p) { lua_remove(L,i); return *p; }\
		else return NULL;\
	} \

#define LDLUA_REGISTER_CLASS(C) { \
		luaL_register (L, #C, C ## _methods); \
		luaL_newmetatable (L, #C); \
		luaL_register (L, NULL, C ## _meta); \
		lua_pushliteral(L, "__index"); \
		lua_pushvalue(L, -3); \
		lua_rawset(L, -3); \
		lua_pushliteral(L, "__metatable");		\
		lua_pushvalue(L, -3); \
		lua_rawset(L, -3); \
		lua_pop(L, 2); \
	}

#define LDLUA_REGISTER_META(C) { \
		luaL_newmetatable (L, #C); \
		luaL_register (L, NULL, C ## _meta); \
		lua_pop(L,1); \
	}

void ldlua_register_classes(lua_State* L);
void ldlua_register_functions(lua_State* L);

#define LDLUA_INIT(L)		   \
	luaL_openlibs(L);		   \
	ldlua_register_classes(L); \
	ldlua_register_functions(L);

int pkb_register(lua_State* L);
int pkbrange_register(lua_State* L);
pkb* push_pkb_to_stack(lua_State* L, pkb pkt);
#endif
