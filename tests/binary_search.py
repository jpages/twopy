# Binary search of an item in a (sorted) list
def binary_search(alist, item):
    first = 0
    last = len(alist) - 1

    found = False

    while first <= last and not found:
        middle = (first + last) // 2

        if alist[middle] == item:
            found = True
        else:
            if item < alist[middle]:
                # Search in the left part
                last = middle - 1
            else:
                first = middle + 1

    return found


alist = [1, 4, 6, 7, 9, 15, 33, 45, 68, 90]
print(binary_search(alist, 68))
