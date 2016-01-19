all_dot := $(wildcard */pattern_*.dot */test.dot)
orig_dot := $(filter-out $(wildcard */*_an.dot), $(all_dot))
annotateddot := $(patsubst %.dot,%_an.dot,$(orig_dot))
TODOT = ../todot

all: $(annotateddot)

%_an.dot: %.dot $(TODOT)
	$(TODOT) $< $@

clean:
	rm -f */*_an.dot

