Sample Project
===  

    g++ -I.. -c sample.cpp
    g++ -L.. -o sample sample.o -lftp++

OSX:
 
    DYLD_LIBRARY_PATH=.. ./sample

LINUX: 

    LD_LIBRARY_PATH=.. ./sample
