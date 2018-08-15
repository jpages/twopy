# If needed with python, modify the recursion limit
# import sys
# sys.setrecursionlimit(1000000)

# Ackermann's Function
def ack(m, n):
    if m == 0:
        return (n + 1)
    elif n == 0:
        return ack(m - 1, 1)
    else:
        return ack(m - 1, ack(m, n - 1))


print(ack(3, 11))
print(ack(3, 11))
print(ack(3, 11))