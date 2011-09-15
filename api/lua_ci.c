#include <assert.h>
#include "lua_ci.h"
#include "common.h"

int ldlua_table_items_num(lua_State *L, char *table_name)
{
	uint32_t proto_num;
	lua_getglobal(L, table_name);
	assert(CHECK_STACK_ITEM(table, L, -1));

	proto_num = lua_objlen(L, -1);
	lua_pop(L, 1);/*balance the stack*/

	return proto_num;
}

int ldlua_table_item_type(lua_State *L, char *table_name, char *item_name)
{
	int type;

	lua_getglobal(L, table_name);
	assert(CHECK_STACK_ITEM(table, L, -1));

	lua_getfield(L, -1, item_name);
	type = lua_type(L, -1);
	lua_pop(L, 1);
	return type;
}

char* ldlua_table_key_get_string(lua_State *L, char *table_name, char *key)
{
	char *p = NULL;
	lua_getglobal(L, table_name);
	assert(CHECK_STACK_ITEM(table, L, -1));
	
	lua_getfield(L, -1, key);
	if (CHECK_STACK_ITEM(string, L, -1)) {
		p = (char *)lua_tostring(L, -1);
	} 
	lua_pop(L, 1);/*balance the stack*/
	return p;
}


char *ldlua_table_raw_get_string(lua_State *L, char *table_name, int index)
{
	char *p = NULL;
	lua_getglobal(L, table_name);
	assert (CHECK_STACK_ITEM(table, L, -1));
	lua_rawgeti(L, -1, index);
	if (CHECK_STACK_ITEM(string, L, -1)) {
		p = (char *)lua_tostring(L, -1);
	} 
	lua_pop(L, 1);/*balance the stack*/
	return p;
}

int ldlua_table_raw_get_number(lua_State *L, char *table_name, int index)
{
	int num;
	lua_getglobal(L, table_name);
	assert (CHECK_STACK_ITEM(table, L, -1));
	lua_rawgeti(L, -1, index);
	if (CHECK_STACK_ITEM(number, L, -1)) {
		num = lua_tonumber(L, -1);
		lua_pop(L, 1);
		return num;
	} else {
		return 0;
	}
}
