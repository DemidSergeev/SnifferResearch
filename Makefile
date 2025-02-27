CXX = g++
CXXFLAGS = -Wall -Wextra -pedantic -std=c++17
LDFLAGS = -lpcap
OBJECTS = main.o packet_sniffer.o packet_handler.o packet_dumper.o \
		  ftp_control_handler.o ftp_data_handler.o other_handler.o \
		  packet_handler_factory.o
TARGET = sniffer.out

$(TARGET): $(OBJECTS)
	$(CXX) -o sniffer.out $(OBJECTS) $(LDFLAGS)
main.o: packet_sniffer.h
packet_sniffer.o: packet_types.h
packet_handler.o: packet_types.h
packet_dumper.o: packet_sniffer.h
ftp_control_handler.o: packet_handler.h packet_dumper.h
ftp_data_handler.o: packet_handler.h packet_dumper.h
other_handler.o: packet_handler.h packet_dumper.h
packet_handler_factory.o: packet_types.h packet_handler.h
clean:
	rm -f $(TARGET) $(OBJECTS)
