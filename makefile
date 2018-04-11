testbinary: main.o base64.o
	gcc -o testbinary main.o base64.o -Os -s -Wall -Wextra 
	rm -rf *.o

main.o: serialization.c
	gcc -o main.o -std=c99 -c serialization.c -Os -s -Wall -Wextra
base64.o: base64.c base64.h
	gcc -o base64.o -c base64.c -Os -s -Wall -Wextra -static 
