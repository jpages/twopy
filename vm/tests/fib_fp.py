def fibR(n):
    if n < 2.0:
        return 1.0
    else:
        return fibR(n-1.0) + fibR(n-2.0)


print(fibR(1.0))
