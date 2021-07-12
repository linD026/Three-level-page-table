all:
	gcc -std=c11 -o test pgtable.c -g -lpthread

addr:
	gcc -std=c11 -o test pgtable.c -g -lpthread -fsanitize=address

clean:
	rm -f test
