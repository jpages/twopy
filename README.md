# twopy
A Python VM based on BBV

### Building
Twopy needs python3 to be launched.
PeachPy, Capstone and cffi are required to build twopy.

To fully install Twopy, follow the next steps:

```bash
git clone https://github.com/python/cpython.git
cd cpython
git checkout 3.7
./configure --without-pymalloc --with-pydebug --prefix=`pwd`/build
make -j16
./python -m ensurepip
./python -m ensurepip --upgrade
./python -m pip install --upgrade git+https://github.com/Maratyszcza/PeachPy
./python -m pip install capstone
./python -m pip install cffi
cd ..
git clone https://github.com/udem-dlteam/twopy.git
cd twopy/vm
```

Create the twopy executable:
```
make
```

Now you can run the command ```./twopy``` to execute a Python file.

### Running

The simple Fibonacci example:
```python
def fib(n):
    if n<2:
        return 1
    else:
        return fib(n-1) + fib(n-2)

print(fibR(40))
```

To launch Twopy on this example and print the time:
```bash
./twopy --time tests/fib.py

165580141

real	0m1,900s
user	0m1,848s
sys	0m0,040s

```
