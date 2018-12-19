def fib_fp(n):
    if n < 2.0:
        return 1.0
    else:
        return fib_fp(n-1.0) + fib_fp(n-2.0)


print(fib_fp(35.0))
