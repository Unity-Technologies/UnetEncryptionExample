
lib=libUnetEncryption.so
deployed_lib=../../../ExampleProject/Assets/Plugins/Linux/$(lib)
# Put your output directory here (e.g. Assets/Plugins dir of your project)

CXXFLAGS+=--std=c++11

CXXFLAGS+=-fPIC
LDFLAGS+=-shared -fPIC

LDLIBS+=-lcrypto -luuid -lpthread

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
	$(RM) $(objs) $(lib)
	@# We don't delete $(deployed_lib), because it could be in a Unity project.
	@# Deleting it would make Unity delete the .meta, losing the user's config.
