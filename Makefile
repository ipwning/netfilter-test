all: nftest

nftest: nftest.o main.o
	g++ -o nftest nftest.o main.o -lnetfilter_queue

main.o: header.h nftest.h main.cpp 

nftest.o: header.h nftest.h nftest.cpp

clean:
	rm -f nftest
	rm -f *.o