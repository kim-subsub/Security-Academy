TARGET=pcap-test
CXXFLAGS=-g
LDLIBS += -lpcap

all: $(TARGET)

$(TARGET): pcap-test.o
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f $(TARGET)
	rm -f *.o

