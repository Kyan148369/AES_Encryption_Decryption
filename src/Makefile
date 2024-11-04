# Compiler flags
CXXFLAGS = -g -Wall -O1 -std=c++11

# For Apple Silicon (M1/M2) Macs
CXXFLAGS += -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib

# Libraries
LIBS = -lcrypto -lssl

# Source files
SOURCES = aes.cpp analyze.cpp bytearray.cpp crypto.cpp dist.cpp prng.cpp

# Object files
OBJECTS = $(SOURCES:.cpp=.o)

# Executables
PROGS = snakeoil bruteforce

all: $(PROGS)

snakeoil: snakeoil.o $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

bruteforce: bruteforce.o $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f *.o $(PROGS)