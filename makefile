mdb: mdb.c
	gcc -Wall mdb.c -lelf -lcapstone -o mdb 