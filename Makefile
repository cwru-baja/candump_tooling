all: $(patsubst %.log,%.json,$(wildcard /mare/candumps/*.log))

%.json:
	./cwrubaja_dump.sh $(patsubst %.json,%.log, $@) > $@ 
