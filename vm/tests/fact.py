def fact(n):
    if n<2:
        return 1
    else:
        return n*fact(n-1)


print(fact(1))
print(fact(5))
print(fact(10))
print(fact(15))
# print(fact(20))
