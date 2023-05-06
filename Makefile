# Compiler options
CXX = g++
CXXFLAGS = -std=c++17 -Wall
LDFLAGS = -lncurses -lpcap

# Source files
SRCS = program.cpp menu.cpp packet_sniffer.cpp

# Object files
OBJS = $(SRCS:.cpp=.o)

# Executable name
EXEC = program

# Rule to build the executable
$(EXEC): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(EXEC) $(LDFLAGS)

# Rule to build object files
%.o: %.cpp %.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -f $(OBJS) $(EXEC)