#pragma once

#ifndef V_MALLOC
#include <stdlib.h>
#include <string.h>
#define V_MALLOC malloc
#define V_REALLOC realloc
#define V_FREE free
#define V_MEMCPY memcpy
#endif
