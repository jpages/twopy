def tak(x, y, z):
    if not y < x:
        return z
    else:
        return tak(tak(x-1, y, z), tak(y-1, z, x), tak(z-1, x, y))


print(tak(9, 6, 3))
print(tak(18, 12, 6))
print(tak(27, 18, 9))
