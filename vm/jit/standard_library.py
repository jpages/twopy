# Standard library of Twopy
# see builtins.py


# Print function, just a placeholder
def twopy_print(objects):
    pass


# Allocate a native array in the heap of given size and returns its tagged address
def allocate_array(size):
    pass


# Access the given native array at given index and return the element
def array_get(array, index):
    pass


# Put the given element in index in a native array
def array_put(array, element, index):
    print(array)
    print(element)
    print(index)

# Class for base object
# class twopy_object:
#     pass
    # """ The most base type """
    #
    # def __delattr__(self, *args, **kwargs):  # real signature unknown
    #     """ Implement delattr(self, name). """
    #     pass
    #
    # def __dir__(self):  # real signature unknown; restored from __doc__
    #     """
    #     __dir__() -> list
    #     default dir() implementation
    #     """
    #     return []
    #
    # def __eq__(self, *args, **kwargs):  # real signature unknown
    #     """ Return self==value. """
    #     pass
    #
    # def __format__(self, *args, **kwargs):  # real signature unknown
    #     """ default object formatter """
    #     pass
    #
    # def __getattribute__(self, *args, **kwargs):  # real signature unknown
    #     """ Return getattr(self, name). """
    #     pass
    #
    # def __ge__(self, *args, **kwargs):  # real signature unknown
    #     """ Return self>=value. """
    #     pass
    #
    # def __gt__(self, *args, **kwargs):  # real signature unknown
    #     """ Return self>value. """
    #     pass
    #
    # def __hash__(self, *args, **kwargs):  # real signature unknown
    #     """ Return hash(self). """
    #     pass
    #
    # def __init_subclass__(self, *args, **kwargs):  # real signature unknown
    #     """
    #     This method is called when a class is subclassed.
    #
    #     The default implementation does nothing. It may be
    #     overridden to extend subclasses.
    #     """
    #     pass
    #
    # def __init__(self):  # known special case of object.__init__
    #     """ Initialize self.  See help(type(self)) for accurate signature. """
    #     pass
    #
    # def __le__(self, *args, **kwargs):  # real signature unknown
    #     """ Return self<=value. """
    #     pass
    #
    # def __lt__(self, *args, **kwargs):  # real signature unknown
    #     """ Return self<value. """
    #     pass
    #
    # @staticmethod  # known case of __new__
    # def __new__(cls, *more):  # known special case of object.__new__
    #     """ Create and return a new object.  See help(type) for accurate signature. """
    #     pass
    #
    # def __ne__(self, *args, **kwargs):  # real signature unknown
    #     """ Return self!=value. """
    #     pass
    #
    # def __reduce_ex__(self, *args, **kwargs):  # real signature unknown
    #     """ helper for pickle """
    #     pass
    #
    # def __reduce__(self, *args, **kwargs):  # real signature unknown
    #     """ helper for pickle """
    #     pass
    #
    # def __repr__(self, *args, **kwargs):  # real signature unknown
    #     """ Return repr(self). """
    #     pass
    #
    # def __setattr__(self, *args, **kwargs):  # real signature unknown
    #     """ Implement setattr(self, name, value). """
    #     pass
    #
    # def __sizeof__(self):  # real signature unknown; restored from __doc__
    #     """
    #     __sizeof__() -> int
    #     size of object in memory, in bytes
    #     """
    #     return 0
    #
    # def __str__(self, *args, **kwargs):  # real signature unknown
    #     """ Return str(self). """
    #     pass
    #
    # @classmethod  # known case
    # def __subclasshook__(cls, subclass):  # known special case of object.__subclasshook__
    #     """
    #     Abstract classes can override this to customize issubclass().
    #
    #     This is invoked early on by abc.ABCMeta.__subclasscheck__().
    #     It should return True, False or NotImplemented.  If it returns
    #     NotImplemented, the normal algorithm is used.  Otherwise, it
    #     overrides the normal algorithm (and the outcome is cached).
    #     """
    #     pass
    #
    # __class__ = None  # (!) forward: type, real value is ''
    # __dict__ = {}
    # __doc__ = ''
    # __module__ = ''


# Class list
class twopy_list():
    def __init__(self, size):
        # Size available in the list for now
        self.twopy_size = size

        self.native_list = allocate_array(size)

    # A list must be iterable
    def twopy_iter(self):
        return self

    # Return the element at given index
    # TODO: handle out of bounds errors
    def list_get(self, index):
        return array_get(self.native_list, index)

    # Insert the given element at index
    # TODO: handle error cases with out of bounds
    def list_put(self, element, index):
        array_put(self.native_list, element, index)


# TODO: make the base class when inheritance is supported
# Class Range
class twopy_range():
    # """
    #     range(stop) -> range object
    #     range(start, stop[, step]) -> range object
    #
    #     Return an object that produces a sequence of integers from start (inclusive)
    #     to stop (exclusive) by step.  range(i, j) produces i, i+1, i+2, ..., j-1.
    #     start defaults to 0, and stop is omitted!  range(4) produces 0, 1, 2, 3.
    #     These are exactly the valid indices for a list of 4 elements.
    #     When step is given, it specifies the increment (or decrement).
    # """
    def __init__(self, stop):
        self.twopy_range_stop = stop

        # By default
        self.twopy_range_start = 0
        self.twopy_range_step = 1

        # The current state of the range if used by an iterator
        self.twopy_range_state = 0

    # Create an iterator from this range object
    def twopy_iter(self):
        # """ Implement iter(self). """
        self.twopy_range_state = self.twopy_range_start

        return self

    # Increment the state of the iterator and returns the next value
    def twopy_next(self):
        value = self.twopy_range_state + self.twopy_range_step

        self.twopy_range_state = value
        if value >= self.twopy_range_stop:
            return False
        else:
            return value
