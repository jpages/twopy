def f(a, b):
    if b % 46 == 41:
        return a - b
    else:
        return a + b


def strange_sum(n):
    result = 0
    while n >= 0:
        result = f(result, n)
        n -= 1
    return result

print(strange_sum(10000000))
