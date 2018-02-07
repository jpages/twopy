# twopy
A Python VM based on BBV

### Building
Twopy works on python3.5 to python 3.6. Capstone and cffi are required to build twopy

```bash
python3 -m pip install capstone
python3 -m pip install cffi
```

### Running

Simple Fibonacci example:
```python
def fib(n):
    if n<2:
        return 1
    else:
        return fib(n-1) + fib(n-2)

print(fibR(40))
```

To launch Twopy with JIT compilation:
```bash
$time python3 ./twopy.py --jit fib.py
165580141

real	0m1,900s
user	0m1,848s
sys	0m0,040s

```
