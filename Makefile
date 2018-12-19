all: twopy

twopy:
	cp main_script.py twopy
	chmod u+x twopy

# Run unit tests
tests:
	rm ./unit-tests/mutable-out -rf
	./run-ut.scm

# Run benchmarks with and without BBV
benchmarks: twopy
	./twopy --time benchmarks/*.py

# Clean
clean:
	rm -rf *~ *.c *.so *.o twopy
