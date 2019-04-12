SUBDIRS := forwarder test
SUBDIRSCLEAN := $(addsuffix clean,$(SUBDIRS))

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@


clean: $(SUBDIRSCLEAN)

%clean:
	$(MAKE) -C $* clean

.PHONY: all $(SUBDIRS)
