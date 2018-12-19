def foo(n):
    res = 0
    for i in range(n):
        res = res + i

    print(res)
    return res


print(foo(10000))
