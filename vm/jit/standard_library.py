# Standard library of twopy
# see builtins.py

# Print function
def twopy_print(objects):
    pass

# Class for base object
class twopy_object:
    """ The most base type """

    def __delattr__(self, *args, **kwargs):  # real signature unknown
        """ Implement delattr(self, name). """
        pass

    def __dir__(self):  # real signature unknown; restored from __doc__
        """
        __dir__() -> list
        default dir() implementation
        """
        return []

    def __eq__(self, *args, **kwargs):  # real signature unknown
        """ Return self==value. """
        pass

    def __format__(self, *args, **kwargs):  # real signature unknown
        """ default object formatter """
        pass

    def __getattribute__(self, *args, **kwargs):  # real signature unknown
        """ Return getattr(self, name). """
        pass

    def __ge__(self, *args, **kwargs):  # real signature unknown
        """ Return self>=value. """
        pass

    def __gt__(self, *args, **kwargs):  # real signature unknown
        """ Return self>value. """
        pass

    def __hash__(self, *args, **kwargs):  # real signature unknown
        """ Return hash(self). """
        pass

    def __init_subclass__(self, *args, **kwargs):  # real signature unknown
        """
        This method is called when a class is subclassed.

        The default implementation does nothing. It may be
        overridden to extend subclasses.
        """
        pass

    def __init__(self):  # known special case of object.__init__
        """ Initialize self.  See help(type(self)) for accurate signature. """
        pass

    def __le__(self, *args, **kwargs):  # real signature unknown
        """ Return self<=value. """
        pass

    def __lt__(self, *args, **kwargs):  # real signature unknown
        """ Return self<value. """
        pass

    @staticmethod  # known case of __new__
    def __new__(cls, *more):  # known special case of object.__new__
        """ Create and return a new object.  See help(type) for accurate signature. """
        pass

    def __ne__(self, *args, **kwargs):  # real signature unknown
        """ Return self!=value. """
        pass

    def __reduce_ex__(self, *args, **kwargs):  # real signature unknown
        """ helper for pickle """
        pass

    def __reduce__(self, *args, **kwargs):  # real signature unknown
        """ helper for pickle """
        pass

    def __repr__(self, *args, **kwargs):  # real signature unknown
        """ Return repr(self). """
        pass

    def __setattr__(self, *args, **kwargs):  # real signature unknown
        """ Implement setattr(self, name, value). """
        pass

    def __sizeof__(self):  # real signature unknown; restored from __doc__
        """
        __sizeof__() -> int
        size of object in memory, in bytes
        """
        return 0

    def __str__(self, *args, **kwargs):  # real signature unknown
        """ Return str(self). """
        pass

    @classmethod  # known case
    def __subclasshook__(cls, subclass):  # known special case of object.__subclasshook__
        """
        Abstract classes can override this to customize issubclass().

        This is invoked early on by abc.ABCMeta.__subclasscheck__().
        It should return True, False or NotImplemented.  If it returns
        NotImplemented, the normal algorithm is used.  Otherwise, it
        overrides the normal algorithm (and the outcome is cached).
        """
        pass

    __class__ = None  # (!) forward: type, real value is ''
    __dict__ = {}
    __doc__ = ''
    __module__ = ''


# Class Range
class twopy_range(twopy_object):
    """
        range(stop) -> range object
        range(start, stop[, step]) -> range object

        Return an object that produces a sequence of integers from start (inclusive)
        to stop (exclusive) by step.  range(i, j) produces i, i+1, i+2, ..., j-1.
        start defaults to 0, and stop is omitted!  range(4) produces 0, 1, 2, 3.
        These are exactly the valid indices for a list of 4 elements.
        When step is given, it specifies the increment (or decrement).
        """

    def count(self, value):  # real signature unknown; restored from __doc__
        """ rangeobject.count(value) -> integer -- return number of occurrences of value """
        return 0

    def index(self, value, start=None, stop=None):  # real signature unknown; restored from __doc__
        """
        rangeobject.index(value, [start, [stop]]) -> integer -- return index of value.
        Raise ValueError if the value is not present.
        """
        return 0

    def __bool__(self, *args, **kwargs):  # real signature unknown
        """ self != 0 """
        pass

    def __contains__(self, *args, **kwargs):  # real signature unknown
        """ Return key in self. """
        pass

    def __eq__(self, *args, **kwargs):  # real signature unknown
        """ Return self==value. """
        pass

    def __getattribute__(self, *args, **kwargs):  # real signature unknown
        """ Return getattr(self, name). """
        pass

    def __getitem__(self, *args, **kwargs):  # real signature unknown
        """ Return self[key]. """
        pass

    def __ge__(self, *args, **kwargs):  # real signature unknown
        """ Return self>=value. """
        pass

    def __gt__(self, *args, **kwargs):  # real signature unknown
        """ Return self>value. """
        pass

    def __hash__(self, *args, **kwargs):  # real signature unknown
        """ Return hash(self). """
        pass

    def __init__(self, stop):  # real signature unknown; restored from __doc__
        pass

    def __iter__(self, *args, **kwargs):  # real signature unknown
        """ Implement iter(self). """
        pass

    def __len__(self, *args, **kwargs):  # real signature unknown
        """ Return len(self). """
        pass

    def __le__(self, *args, **kwargs):  # real signature unknown
        """ Return self<=value. """
        pass

    def __lt__(self, *args, **kwargs):  # real signature unknown
        """ Return self<value. """
        pass

    @staticmethod  # known case of __new__
    def __new__(*args, **kwargs):  # real signature unknown
        """ Create and return a new object.  See help(type) for accurate signature. """
        pass

    def __ne__(self, *args, **kwargs):  # real signature unknown
        """ Return self!=value. """
        pass

    def __reduce__(self, *args, **kwargs):  # real signature unknown
        pass

    def __repr__(self, *args, **kwargs):  # real signature unknown
        """ Return repr(self). """
        pass

    def __reversed__(self, *args, **kwargs):  # real signature unknown
        """ Return a reverse iterator. """
        pass

    start = 0

    step = 1

    stop = None
