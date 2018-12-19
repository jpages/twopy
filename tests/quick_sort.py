import random


# Very inefficient bubble sort
def bubble_sort(array):
    for i in range(len(array)):
        for j in range(i, len(array)):
            if array[i] > array[j]:
                # Swap these elements
                temp = array[i]
                array[i] = array[j]
                array[j] = temp
    return array


# More efficient quick sort (with a pivot)
def quick_sort(array):
    less = []
    equal = []
    greater = []

    if len(array) > 1:
        # Chose a pivot
        pivot = array[0]
        for x in array:
            if x < pivot:
                less.append(x)
            if x == pivot:
                equal.append(x)
            if x > pivot:
                greater.append(x)
        return quick_sort(less) + equal + quick_sort(greater)
    else:
        return array


random.seed()

array = [12, 4, 5, 6, 7, 3, 1, 15]

for i in range(10000):
    array.append(int(random.random()*100000))

print(quick_sort(array))
print(bubble_sort(array))
