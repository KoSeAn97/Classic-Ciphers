cxx = g++
cxxflags = -std=gnu++11

srcs = main.cpp ciphers.cpp
hdrs = ciphers.hpp
objs = $(srcs:.cpp=.o)

program: $(objs)
	$(cxx) $^ -o $@
main.o: main.cpp ciphers.hpp
	$(cxx) $(cxxflags) $< -c -o $@
ciphers.o: ciphers.cpp ciphers.hpp
	$(cxx) $(cxxflags) $< -c -o $@

.PHONY: clean all
all: program
clean:
	$(RM) $(objs) program
