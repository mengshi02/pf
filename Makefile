name :=pf

BIN=/usr/local/bin
CARGO=

debug ?=

ifdef debug
  release :=
  target :=debug
  extension :=debug
else
  release :=--release
  target :=release
  extension :=
endif

CMDs = pf

build:
	$(CARGO)cargo build $(release)

.PHONY: $(CMDs)

install: $(CMDs)
	for CMD in $^ ; do \
    	cp target/$(target)/$$CMD $(BIN); \
	done

clean:
	$(CARGO)/cargo clean

uninstall: clean
	for var in $(CMDs) ; do rm -rf  $(BIN)/$$var; done

all: build install

help:
	@echo "usage: make $(name) [debug=1]"
