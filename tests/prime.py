def primes(value):
    for num in range(value):
        res = True
        for k in range(2, num):
            if k != 0:
                if num % k == 0:
                    res = False

        if res == True:
            print(num)


primes(100)
