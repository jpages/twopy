'''
This module contains the model creation: functions, basic-blocks and instructions
'''

from types import *

class MModule:
    '''
    Represent a python module, contain code
    self.code = Code Object of the module
    '''
    def __init__(self, code):
        self.code = code

        # All functions defined in this module
        self.functions = []

        # The corresponding python Module
        self.pythonmodule = None

    # Add a new compiled function to the module
    def add_function(self, function):
        self.functions.append(function)

    def lookup(self, name, is_main):
        for fun in self.functions:
            # We are not looking for top-level functions
            if fun.name == name and not fun.is_main:
                return fun

        assert "Function not found"


# The class of python classes
class MClass:

    def __init__(self, interpreter, mainfunc, name, *superclasses, metaclass=None, **kwds):
        self.mainfunction = mainfunc
        self.name = name
        self.superclasses = superclasses
        self.metaclass = metaclass
        self.kwds = kwds

        self.interpreter = interpreter

        # All instances of this class, beware of memory here
        self.instances = []

        # For now, implement methods with a simple dictionnary between name and functions
        self.methods = {}

        # Now execute this class and fill the environment
        env = {}
        env["__name__"] = name

        mainfunc.as_class(self)

        mainfunc.environments.append(env)
        interpreter.environments.append(env)

        # Make the call
        mainfunc.execute(interpreter)

    # Add an attribute "tos" named "name" to this class
    def add_attribute(self, name, attr):
        # We are adding a method to the class
        if isinstance(attr, Function):
            self.methods[name] = attr
        else:
            # TODO: maybe do something here
            pass

    # Create a return a new Instance of this class
    def new_instance_interpreter(self, *attrs):
        mobject = MObject(self, attrs)

        self.instances.append(mobject)

        # Now we need to call the constructor of the class for this object
        # Get and execute the constructor
        init = self.methods["__init__"]
        env = {}

        # Construct environment for the call
        init.environments.append(env)
        self.interpreter.environments.append(env)

        # adding self to arguments of the constructor
        args = []
        args.append(mobject)
        for el in attrs: args.append(el)

        # Fill the environment
        for i in range(0, len(args)):
            env[init.varnames[i]] = args[i]

        # Call the initializer
        init.execute(self.interpreter)

        # Remove the None value on the top of stack
        self.interpreter.pop()

        return mobject

# An instance of a MClass
class MObject:
    def __init__(self, mclass, *attrs):
        self.mclass = mclass

        # TODO: better implementation of attributes
        self.attributes = {}

    # Return the property corresponding to the name in parameter
    def get_property(self, name):
        # Look in the class for a method
        if name in self.mclass.methods:
            return self.mclass.methods[name]
        else:
            return self.attributes[name]

    # Set the value for the attribute named "name"
    def set_attribute(self, name, value):
        self.attributes[name] = value


class Function:
    '''
    Represent a function

    self.id_function = Identifier of the function, used to make calls
    self.argcount = number of arguments
    self.kwonlyargcount = number of keyword arguments
    self.nlocals = number of local variables
    self.stacksize = virtual machine stack space required
    self.consts = tuple of constants used in the bytecode
    self.names = tuple of names of local variables
    self.varnames = tuple of names of arguments and local variables
    self.freevars = tuple of names of variables used by parent scope
    self.cellvars = tuple of names of variables used by child scopes
    self.name = Function name
    self.iterator = Iterator over Instructions
    self.interpreter = The interpreter instance
    self.module = The Module instance in which this function was defined
    self.is_main = True if the function is top-level of a module
    '''
    def __init__(self, id_function, argcount, kwonlyargcount,
                nlocals, stacksize, consts, names, varnames, freevars,
                cellvars, name, iterator, interpreter, module, is_main):
        self.id_function = id_function
        self.argcount = argcount
        self.kwonlyargcount = kwonlyargcount
        self.nlocals = nlocals
        self.stacksize = stacksize
        self.consts = consts
        self.names = names
        self.varnames = varnames
        self.freevars = freevars
        self.cellvars = cellvars
        self.name = name
        self.iterator = iterator
        self.interpreter = interpreter
        self.module = module
        self.is_main = is_main

        self.nb_pure_locals = nlocals - argcount

        # Environments are linked for each call
        self.environments = []

        self.generate_instructions()
        self.generate_basic_blocks()

        # Dictionnary of freecells and their values
        self.closure = {}

        # Add the current function to the module
        module.add_function(self)

        # Indicate if this Function is a Class
        self.is_class = False

        # If this value is set, then it's a method and receiver will be used as
        # self
        self.receiver = None
        self.allocator = None

    def generate_instructions(self):
        # temporary, all instructions of the function without basic blocks
        self.all_instructions = []

        temp_instructions = []
        for o in self.iterator:
            temp_instructions.append(o)

        # The next opcode, to compute size of instructions
        next_op = None

        # Iterate over opcodes and create Instruction classes
        for i in range(0, len(temp_instructions)):
            op = temp_instructions[i]

            if i < len(temp_instructions)-1:
                next_op = temp_instructions[i+1]

            size = next_op.offset - op.offset

            if self.interpreter.args.verbose:
                print(str(op) + ", size " + str(size))

            instruction = dict_instructions[op.opcode](op.offset,
            op.opcode, op.opname, op.arg, op.is_jump_target, size)

            instruction.function = self

            self.all_instructions.append(instruction)

    # Generate basic blocks in the function
    def generate_basic_blocks(self):
        # The entry point of the function
        self.start_basic_block = BasicBlock(self)

        # Association between jump instruction and their target
        jumps = {}

        # Current is the current block, will be filled until a branching instruction
        current = self.start_basic_block

        for i in range(0, len(self.all_instructions)):
            instruction = self.all_instructions[i]
            current.add_instruction(instruction)

            if instruction.is_branch():
                # Finish the current block and create a new one
                new_block = BasicBlock(self)
                current.link_to(new_block)
                current = new_block

            if instruction.is_jump():
                # Save this instruction and its target
                jumps[instruction.absolute_target] = instruction

        # Now we need to reiterate over instructions to associate jumps to their targets
        for i in range(0, len(self.all_instructions)):
            instruction = self.all_instructions[i]

            # Put the target of a jump in a new block with its following
            # instructions (if any) and link all blocks
            if instruction.offset in jumps:
                jump = jumps[instruction.offset]
                old_block = instruction.block

                new_block = BasicBlock(self)
                for next_block in instruction.block.next:
                    new_block.link_to(next_block)

                instruction.block.link_to(new_block)

                # Append to the jump block the new block
                jump.block.link_to(new_block)

                # Now split the previous block
                temp_instructions = []
                for i in range(instruction.block.instructions.index(instruction), len(instruction.block.instructions)):
                    temp_instructions.append(instruction.block.instructions[i])

                for t in temp_instructions:
                    old_block.instructions.remove(t)
                    new_block.add_instruction(t)

                # The old block must jump to the newly created block
                target = new_block.instructions[0].offset

                # Add a new fake jump with special values
                jump = JUMP_ABSOLUTE(-1, 113, "JUMP_ABSOLUTE", target, False, 3)
                old_block.add_instruction(jump)

                jump.block.link_to(old_block)

                # Finally, the old block must not be linked with itself but with the new one
                if len(old_block.instructions) >= 2 and isinstance(old_block.instructions[-2], GET_ITER):

                    if old_block in old_block.next:
                        old_block.next.remove(old_block)

                    if old_block in old_block.previous:
                        old_block.previous.remove(old_block)

    # If called, this Function is the main one of the class in parameter
    def as_class(self, mclass):
        self.mclass = mclass

        self.is_class = True

    # Print the current Function and its basic blocks
    def __repr__(self):
        s = "Function " + (self.name)

        return s


class BasicBlock:
    '''
        Represent a basic block : a sequence of instructions without a jump
        until the end. Basic blocks are link together and form a graph

        self.function = The function
        self.previous = previous basic blocks
        self.next = next basic blocks
        instructions = the list of instructions in order
    '''
    def __init__(self, fun):
        self.function = fun
        self.previous = set()
        self.next = set()
        self.instructions = []

        # Used for the JIT
        self.compiled = False

    def add_instruction(self, instruction):
        # type: (object) -> object
        self.instructions.append(instruction)
        instruction.block = self

    # Link the self basic block to next
    # self will be a predecessor of next
    def link_to(self, next_bb):
        self.next.add(next_bb)
        next_bb.previous.add(self)

    def __repr__(self):
        s = "previous : "
        for p in self.previous:
            s += str(id(p)) + ", "

        s += "\n" + "next : "
        for n in self.next:
            s += (str(id(n))) + ", "

        s += "\n"
        for instruction in self.instructions:
            s += str(instruction) + "\n"
        return s


# The root of all instructions
class Instruction:
    '''
    Represents an instruction based on an opcode from bytecode

        self.offset = offset of the opcode from the beginning of the function
        self.opcode_number = number of the opcode
        self.opcode_string = string with opcode name
        self.arguments = Python object with argument, will be None for
                        opcodes without arguments
        self.is_jump_target = True is this instruction is a jump target
        self.size = number of bytes used by the opcode
    '''
    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        self.offset = offset
        self.opcode_number = opcode_number
        self.opcode_string = opcode_string
        self.arguments = arguments
        self.is_jump_target = is_jump_target
        self.size = size

        # The basic block containing this instruction
        self.block = None

        # The function of this Instruction
        self.function = None

        self.compiled = 0

    def __repr__(self):
        s = str(self.__class__) + ", offset = " + str(self.offset)
        s += ", opcode = " + str(self.opcode_number)
        s += ", opcode_string = " + self.opcode_string
        s += ", argument = " + str(self.arguments)

        return s

    # Return true if self is a branching instruction, false otherwise
    def is_branch(self):
        return isinstance(self, BranchInstruction)

    # Return true if self is a jumping instruction, false otherwise
    def is_jump(self):
        return isinstance(self, JumpInstruction)

# A particular class which breaks the control flow of a basic block by branching
class BranchInstruction(Instruction):
    pass


# A Branching instruction that can change the bytecode counter either by a
# relative or an absolute offset
class JumpInstruction(BranchInstruction):

    # Compute absolute_target, the absolute target of the jump of this Instruction
    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = -1

    def __repr__(self):
        s = super().__repr__()
        s += ", absolute_target " + str(self.absolute_target)

        return s


class POP_TOP(Instruction):
    pass


class ROT_TWO(Instruction):
    pass


class ROT_THREE(Instruction):
    pass


class DUP_TOP(Instruction):
    pass


class DUP_TOP_TWO(Instruction):
    pass


class NOP(Instruction):
    pass


class UNARY_POSITIVE(Instruction):
    pass


class UNARY_NEGATIVE(Instruction):
    pass


class UNARY_NOT(Instruction):
    pass


class UNARY_INVERT(Instruction):
    pass


class BINARY_MATRIX_MULTIPLY(Instruction):
    pass


class INPLACE_MATRIX_MULTIPLY(Instruction):
    pass


class BINARY_POWER(Instruction):
    pass


class BINARY_MULTIPLY(Instruction):
    pass


class BINARY_MODULO(Instruction):
    pass


class BINARY_ADD(Instruction):
    pass


class BINARY_SUBTRACT(Instruction):
    pass


class BINARY_SUBSCR(Instruction):
    pass

class BINARY_FLOOR_DIVIDE(Instruction):
    pass


class BINARY_TRUE_DIVIDE(Instruction):
    pass


class INPLACE_FLOOR_DIVIDE(Instruction):
    pass


class INPLACE_TRUE_DIVIDE(Instruction):
    pass


class GET_AITER(Instruction):
    pass


class GET_ANEXT(Instruction):
    pass


class BEFORE_ASYNC_WITH(Instruction):
    pass


class INPLACE_ADD(Instruction):
    pass


class INPLACE_SUBTRACT(Instruction):
    pass


class INPLACE_MULTIPLY(Instruction):
    pass


class INPLACE_MODULO(Instruction):
    pass


class STORE_SUBSCR(Instruction):
    pass


class DELETE_SUBSCR(Instruction):
    pass


class BINARY_LSHIFT(Instruction):
    pass


class BINARY_RSHIFT(Instruction):
    pass


class BINARY_AND(Instruction):
    pass


class BINARY_XOR(Instruction):
    pass


class BINARY_OR(Instruction):
    pass


class INPLACE_POWER(Instruction):
    pass


class GET_ITER(Instruction):
    pass


class GET_YIELD_FROM_ITER(Instruction):
    pass


class PRINT_EXPR(Instruction):
    pass


class LOAD_BUILD_CLASS(Instruction):
    pass


class YIELD_FROM(Instruction):
    pass


class GET_AWAITABLE(Instruction):
    pass


class INPLACE_LSHIFT(Instruction):
    pass


class INPLACE_RSHIFT(Instruction):
    pass


class INPLACE_AND(Instruction):
    pass


class INPLACE_XOR(Instruction):
    pass


class INPLACE_OR(Instruction):
    pass


class BREAK_LOOP(Instruction):
    pass


class WITH_CLEANUP_START(Instruction):
    pass


class WITH_CLEANUP_FINISH(Instruction):
    pass


class RETURN_VALUE(BranchInstruction):
    pass


class IMPORT_STAR(Instruction):
    pass


class SETUP_ANNOTATIONS(Instruction):
    pass


class YIELD_VALUE(BranchInstruction):
    pass


class POP_BLOCK(Instruction):
    pass


class END_FINALLY(Instruction):
    pass


class POP_EXCEPT(Instruction):
    pass


class HAVE_ARGUMENT(Instruction):
    pass


class STORE_NAME(Instruction):
    pass


class DELETE_NAME(Instruction):
    pass


class UNPACK_SEQUENCE(Instruction):
    pass


class FOR_ITER(JumpInstruction):
    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = offset + arguments + size


class UNPACK_EX(Instruction):
    pass


class STORE_ATTR(Instruction):
    pass


class DELETE_ATTR(Instruction):
    pass


class STORE_GLOBAL(Instruction):
    pass


class DELETE_GLOBAL(Instruction):
    pass


class LOAD_CONST(Instruction):
    pass


class LOAD_NAME(Instruction):
    pass


class BUILD_TUPLE(Instruction):
    pass


class BUILD_LIST(Instruction):
    pass


class BUILD_SET(Instruction):
    pass


class BUILD_MAP(Instruction):
    pass


class LOAD_ATTR(Instruction):
    pass


class COMPARE_OP(Instruction):
    pass


class IMPORT_NAME(Instruction):
    pass


class IMPORT_FROM(Instruction):
    pass


class JUMP_FORWARD(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = offset + arguments + size


class JUMP_IF_FALSE_OR_POP(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = arguments


class JUMP_IF_TRUE_OR_POP(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = arguments


class JUMP_ABSOLUTE(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = arguments


class POP_JUMP_IF_FALSE(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = arguments


class POP_JUMP_IF_TRUE(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = arguments


class LOAD_GLOBAL(Instruction):
    pass


class CONTINUE_LOOP(Instruction):
    pass


class SETUP_LOOP(Instruction):
    pass


class SETUP_EXCEPT(Instruction):
    pass


class SETUP_FINALLY(Instruction):
    pass


class LOAD_FAST(Instruction):
    pass


class STORE_FAST(Instruction):
    pass


class DELETE_FAST(Instruction):
    pass


class STORE_ANNOTATION(Instruction):
    pass


class RAISE_VARARGS(BranchInstruction):
    pass


class CALL_FUNCTION(Instruction):
    pass


class MAKE_FUNCTION(Instruction):
    pass


class BUILD_SLICE(Instruction):
    pass


class LOAD_CLOSURE(Instruction):
    pass

class LOAD_DEREF(Instruction):
    pass


class STORE_DEREF(Instruction):
    pass


class DELETE_DEREF(Instruction):
    pass


class CALL_FUNCTION_KW(Instruction):
    pass


class CALL_FUNCTION_EX(Instruction):
    pass


class SETUP_WITH(Instruction):
    pass


class EXTENDED_ARG(Instruction):
    pass


class LIST_APPEND(Instruction):
    pass


class SET_ADD(Instruction):
    pass


class MAP_ADD(Instruction):
    pass


class LOAD_CLASSDEREF(Instruction):
    pass


class BUILD_LIST_UNPACK(Instruction):
    pass


class BUILD_MAP_UNPACK(Instruction):
    pass


class BUILD_MAP_UNPACK_WITH_CALL(Instruction):
    pass


class BUILD_TUPLE_UNPACK(Instruction):
    pass


class BUILD_SET_UNPACK(Instruction):
    pass


class SETUP_ASYNC_WITH(Instruction):
    pass


class FORMAT_VALUE(Instruction):
    pass


class BUILD_CONST_KEY_MAP(Instruction):
    pass


class BUILD_STRING(Instruction):
    pass


class BUILD_TUPLE_UNPACK_WITH_CALL(Instruction):
    pass



# Dictionary between instruction classes and opcode numbers
dict_instructions = {
1 : POP_TOP,
2 : ROT_TWO,
3 : ROT_THREE,
4 : DUP_TOP,
5 : DUP_TOP_TWO,
9 : NOP,
10 : UNARY_POSITIVE,
11 : UNARY_NEGATIVE,
12 : UNARY_NOT,
15 : UNARY_INVERT,
16 : BINARY_MATRIX_MULTIPLY,
17 : INPLACE_MATRIX_MULTIPLY,
19 : BINARY_POWER,
20 : BINARY_MULTIPLY,
22 : BINARY_MODULO,
23 : BINARY_ADD,
24 : BINARY_SUBTRACT,
25 : BINARY_SUBSCR,
26 : BINARY_FLOOR_DIVIDE,
27 : BINARY_TRUE_DIVIDE,
28 : INPLACE_FLOOR_DIVIDE,
29 : INPLACE_TRUE_DIVIDE,
50 : GET_AITER,
51 : GET_ANEXT,
52 : BEFORE_ASYNC_WITH,
55 : INPLACE_ADD,
56 : INPLACE_SUBTRACT,
57 : INPLACE_MULTIPLY,
59 : INPLACE_MODULO,
60 : STORE_SUBSCR,
61 : DELETE_SUBSCR,
62 : BINARY_LSHIFT,
63 : BINARY_RSHIFT,
64 : BINARY_AND,
65 : BINARY_XOR,
66 : BINARY_OR,
67 : INPLACE_POWER,
68 : GET_ITER,
69 : GET_YIELD_FROM_ITER,
70 : PRINT_EXPR,
71 : LOAD_BUILD_CLASS,
72 : YIELD_FROM,
73 : GET_AWAITABLE,
75 : INPLACE_LSHIFT,
76 : INPLACE_RSHIFT,
77 : INPLACE_AND,
78 : INPLACE_XOR,
79 : INPLACE_OR,
80 : BREAK_LOOP,
81 : WITH_CLEANUP_START,
82 : WITH_CLEANUP_FINISH,
83 : RETURN_VALUE,
84 : IMPORT_STAR,
85 : SETUP_ANNOTATIONS,
86 : YIELD_VALUE,
87 : POP_BLOCK,
88 : END_FINALLY,
89 : POP_EXCEPT,
90 : HAVE_ARGUMENT,
90 : STORE_NAME,
91 : DELETE_NAME,
92 : UNPACK_SEQUENCE,
93 : FOR_ITER,
94 : UNPACK_EX,
95 : STORE_ATTR,
96 : DELETE_ATTR,
97 : STORE_GLOBAL,
98 : DELETE_GLOBAL,
100 : LOAD_CONST,
101 : LOAD_NAME,
102 : BUILD_TUPLE,
103 : BUILD_LIST,
104 : BUILD_SET,
105 : BUILD_MAP,
106 : LOAD_ATTR,
107 : COMPARE_OP,
108 : IMPORT_NAME,
109 : IMPORT_FROM,
110 : JUMP_FORWARD,
111 : JUMP_IF_FALSE_OR_POP,
112 : JUMP_IF_TRUE_OR_POP,
113 : JUMP_ABSOLUTE,
114 : POP_JUMP_IF_FALSE,
115 : POP_JUMP_IF_TRUE,
116 : LOAD_GLOBAL,
119 : CONTINUE_LOOP,
120 : SETUP_LOOP,
121 : SETUP_EXCEPT,
122 : SETUP_FINALLY,
124 : LOAD_FAST,
125 : STORE_FAST,
126 : DELETE_FAST,
127 : STORE_ANNOTATION,
130 : RAISE_VARARGS,
131 : CALL_FUNCTION,
132 : MAKE_FUNCTION,
133 : BUILD_SLICE,
135 : LOAD_CLOSURE,
136 : LOAD_DEREF,
137 : STORE_DEREF,
138 : DELETE_DEREF,
141 : CALL_FUNCTION_KW,
142 : CALL_FUNCTION_EX,
143 : SETUP_WITH,
144 : EXTENDED_ARG,
145 : LIST_APPEND,
146 : SET_ADD,
147 : MAP_ADD,
148 : LOAD_CLASSDEREF,
149 : BUILD_LIST_UNPACK,
150 : BUILD_MAP_UNPACK,
151 : BUILD_MAP_UNPACK_WITH_CALL,
152 : BUILD_TUPLE_UNPACK,
153 : BUILD_SET_UNPACK,
154 : SETUP_ASYNC_WITH,
155 : FORMAT_VALUE,
156 : BUILD_CONST_KEY_MAP,
157 : BUILD_STRING,
158 : BUILD_TUPLE_UNPACK_WITH_CALL,

# Special extensions to use pypy for starting twopy
201 : LOAD_ATTR,
202 : CALL_FUNCTION,
}
