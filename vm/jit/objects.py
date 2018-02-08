'''
This module contains the representations used by the JIT compiler
'''


# Define methods to tag and untag objects
class TagHandler:

    # TAGS :
    # 00    int
    # 01    specials like char and boolean
    # 10    memory objects
    def __init__(self):
        #TODO: define relation betweens types and their tags
        pass

    # Tag an integer
    def tag_integer(self, value):
        return value * 4

    # Untag an integer
    def untag_integer(self):
        pass

    def tag_float(self):
        pass

    def untag_float(self):
        pass


class Object:
    def __init__(self):
        pass


class Numeric(Object):
    def __init__(self):
        pass


class Integer(Numeric):
    def __init__(self):
        pass


class Float(Numeric):
    def __init__(self):
        pass