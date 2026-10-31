CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2

VERSION = 1.0.0
NAME = audisp-strace

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
PLUGINDIR ?= $(SYSCONFDIR)/audit/plugins.d
DESTDIR ?=

INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL) -m 755
INSTALL_DATA ?= $(INSTALL) -m 644
INSTALL_CONF ?= $(INSTALL) -m 640

TARGET = test_syscalls
SRC = test_syscalls.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
	rm -rf rpmbuild $(NAME)-*.tar.gz

test:
	python3 -m unittest discover tests -v

install:
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL_PROGRAM) $(NAME) $(DESTDIR)$(BINDIR)/$(NAME)
	$(INSTALL) -d $(DESTDIR)$(PLUGINDIR)
	sed 's|^path = .*|path = $(BINDIR)/$(NAME)|' $(NAME).conf > $(DESTDIR)$(PLUGINDIR)/$(NAME).conf
	chmod 640 $(DESTDIR)$(PLUGINDIR)/$(NAME).conf

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(NAME)
	rm -f $(DESTDIR)$(PLUGINDIR)/$(NAME).conf

dist:
	@mkdir -p $(NAME)-$(VERSION)
	@cp -a $(NAME) $(NAME).conf $(NAME).spec LICENSE Makefile README.md todo tests $(NAME)-$(VERSION)/
	@find $(NAME)-$(VERSION) -name '__pycache__' -o -name '*.pyc' -o -name '*.swp' | xargs rm -rf
	@tar -czf $(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	@rm -rf $(NAME)-$(VERSION)
	@echo "Created $(NAME)-$(VERSION).tar.gz"

srpm: dist
	@mkdir -p rpmbuild/BUILD rpmbuild/RPMS rpmbuild/SOURCES rpmbuild/SPECS rpmbuild/SRPMS
	@cp $(NAME)-$(VERSION).tar.gz rpmbuild/SOURCES/
	@cp $(NAME).spec rpmbuild/SPECS/
	rpmbuild -bs --define "_topdir $(CURDIR)/rpmbuild" rpmbuild/SPECS/$(NAME).spec
	@echo "SRPM build complete: $$(find $(CURDIR)/rpmbuild/SRPMS -name '*.src.rpm')"

rpm: dist
	@mkdir -p rpmbuild/BUILD rpmbuild/RPMS rpmbuild/SOURCES rpmbuild/SPECS rpmbuild/SRPMS
	@cp $(NAME)-$(VERSION).tar.gz rpmbuild/SOURCES/
	@cp $(NAME).spec rpmbuild/SPECS/
	rpmbuild -ba --define "_topdir $(CURDIR)/rpmbuild" rpmbuild/SPECS/$(NAME).spec
	@echo "RPM build complete: $$(find $(CURDIR)/rpmbuild/RPMS -name '*.rpm')"

.PHONY: all clean test install uninstall dist srpm rpm
