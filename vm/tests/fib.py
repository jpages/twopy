def fact(n):
    if n<2:
        return 1
    else:
        return n*fact(n-1)

def fib(n):
    a,b = 1,1
    for i in range(n):
        a,b = b,a+b
    return a

def fibR(n):
    if n<2:
        return 1
    else:
        return fibR(n-1)+fibR(n-2)

print(fact(5))

fact(5)

print(fib(100))
print(fib(10))
print(fibR(10))
