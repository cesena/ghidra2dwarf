#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

typedef struct example {
	int x;
	int y;
	char *name;
} EXAMPLE;

typedef struct dummy {
	int a;
	int b;
	int c;
} DUMMY;

EXAMPLE *ex_1;

EXAMPLE *dup_example(EXAMPLE *ex) {
	/* Use this structure not in a return type */
	DUMMY *dum = malloc(sizeof(DUMMY));
	dum->a = 10;
	EXAMPLE *new = malloc(sizeof(EXAMPLE));
	new->x = ex->x;
	new->y = ex->y;
	new->name = ex->name;
	return new;
}

void print_example(EXAMPLE *ex) {
	printf("x: %d\ty: %d\tname: %s\n", ex->x, ex->y, ex->name);
}

int main(int argc, char **argv) {
	int i = 0;
	ex_1 = malloc(sizeof(EXAMPLE));
	ex_1->x = 10;
	for (i = 0; i < 5; i++) {
		ex_1->x++;
	}
	ex_1->y = 20;
	ex_1->name = "Example 1";
	print_example(ex_1);
	EXAMPLE *ex_2 = dup_example(ex_1);
	ex_2->name = "Example 2";
	ex_2->y += ex_2->x;
	print_example(ex_2);
    return 0;
}

