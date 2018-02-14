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
        return value
        #return value << 2

    # Untag an integer
    def untag_integer(self, value):
        return value >> 2

    # 101 -> True
    # OO1 -> False
    def tag_bool(self, value):
        tag_value = value << 2
        tag_value = tag_value | 1

        return tag_value

    def untag_bool(self, value):
        untag_value = value >> 2
        untag_value = untag_value & 0

        return untag_value

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