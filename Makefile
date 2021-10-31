all: netfilter-test

netfilter-test: netfilter-test.o main.o
	g++ -o netfilter-test netfilter-test.o main.o -lnetfilter_queue

main.o: header.h netfilter-test.h main.cpp 

netfilter-test.o: header.h netfilter-test.h netfilter-test.cpp

clean:
	rm -f netfilter-test
	rm -f *.o
