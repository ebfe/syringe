#include <stdio.h>

__attribute__((constructor)) void sayhello () {
	puts("hello world!");
}
