class Animal:
    pass

class Dog(Animal):

    def __init__(self, name):
        self.name = name
        self.tricks = []    # creates a new empty list for each dog

    def add_trick(self, trick):
        self.tricks.append(trick)

    def foo(self):
        print(self)

    print("test")

d = Dog('Fido')
e = Dog('Buddy')

d.add_trick('roll over')
d.add_trick('another trick')

e.add_trick('play dead')

e.foo()

print(d.tricks)
print(e.tricks)
