
lib=libUnetEncryption.so
deployed_lib=$(lib)
# Put your output directory here (e.g. Assets/Plugins dir of your project)

CXXFLAGS+=--std=c++11

CXXFLAGS+=-fPIC
LDFLAGS+=-shared -fPIC

LDLIBS+=-lcrypto -luuid

CPPFLAGS+=-I../../Shared/

CXXFLAGS += -g -O0

all: $(deployed_lib)

srcs+=$(wildcard *.cpp)
objs=$(subst .cpp,.o, $(srcs))

$(lib) : $(objs)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)


$(deployed_lib) : $(lib)
	@mkdir -p $(dir $@)
	cp -v $< $@


.PHONY: clean
clean:
	$(RM) $(objs) $(lib) $(deployed_lib)
