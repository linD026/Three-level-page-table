addr:
	gcc -std=c11 -o test pgtable.c -g -lpthread -fsanitize=address

make:
	gcc -std=c11 -o test pgtable.c -g -lpthread
