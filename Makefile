CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
LDLIBS = -lpcap

TARGET = tcp-block
SRC = main.cpp

all: $(TARGET)

$(TARGET): $(SRC) ethhdr.h iphdr.h tcphdr.h
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDLIBS)

clean:
	rm -f $(TARGET)