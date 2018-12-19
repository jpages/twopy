def fact(n):
    if n<2:
        return 1
    else:
        return n*fact(n-1)


print(fact(5))
print(fact(1))
print(fact(20))

print(fact(-10))

#120
#1
#2432902008176640000
#1
