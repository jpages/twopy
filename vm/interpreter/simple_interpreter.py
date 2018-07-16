# An interpreter-only virtual machine

from types import *
import dis
import importlib

import frontend
from frontend import model

# The singleton of the Interpreter
simple_interpreter_instance = None

def get_interpreter(maincode, subdirectory, args):
    global simple_interpreter_instance
    if simple_interpreter_instance == None:
        simple_interpreter_instance = SimpleInterpreter(maincode, subdirectory, args)

    return simple_interpreter_instance


class SimpleInterpreter:
    def __init__(self, maincode, subdirectory, args):
        # The main CodeObject
        self.maincode = maincode
        self.mainmodule = model.MModule(maincode)

        # All loaded modules
        self.modules = []
        self.modules.append(self.mainmodule)

        # The directory of the executed file
        self.subdirectory = subdirectory

        # Command-line arguments for the vm
        self.args = args

        # An identifier incremented for each function, main has 0
        self.global_id_function = 0

        # A list indexed by function identifiers, the first one has indice 0
        self.functions = []

        # The global environment
        self.global_environment = {}

        # List of all environments, the last one is the current call
        self.environments = []

        self.functions_called = []

        # The Jit compiler instance, will be set by the launcher
        self.jitcompiler = None

        # Association between a Code object and a Function object to avoid duplication
        self.code_to_function = dict()

    # Iterate over opcodes and execute the code
    def execute(self):
        # Precompile the code by generating proper instructions and basic blocks
        self.precompile()

        # Start the execution
        self.start()

    def precompile(self):
        # Generate the main function and recursively other functions in module
        self.generate_function(self.maincode, "main", self.mainmodule, True)

        # TODO: use identifiers instead of names to call functions

    # code : the CodeObject of this function
    # name : Function name
    # module : the Module instance
    # is_main : true if the function is top-level of a module
    def generate_function(self, code, name, module, is_main):

        if code in self.code_to_function:
            return self.code_to_function[code]

        function = model.Function(self.global_id_function, code.co_argcount,
    code.co_kwonlyargcount, code.co_nlocals, code.co_stacksize, code.co_consts,
    code.co_names, code.co_varnames, code.co_freevars, code.co_cellvars,
    name, dis.get_instructions(code), self, module, is_main)

        self.code_to_function[code] = function
        self.functions.append(function)

        if self.args.verbose:
            print(dis.dis(code))

        # Increment the global function id
        self.global_id_function += 1

        return function

    # Start the execution after the compilation of functions
    def start(self):
        # Start from the main (toplevel) function
        # The execution stack
        self.stack = []

        self.functions_called.append(self.functions[0])

        env = {}
        self.current_function().environments.append(env)
        self.environments.append(env)

        # Initialize primitive functions
        for key, value in primitives.items():
            self.global_environment[key] = value

        self.execute_function(self.functions[0])

    # Return the function currently called, the last one on the stack
    def current_function(self):
        return self.functions_called[-1]

    ''' Generate a new class and return it
        func = main function of the class
        name = class name
        bases = direct superclasses
        metaclass = The metaclass
    '''
    def make_class(self, func, name, *bases, metaclass=None, **kwds):
        return model.MClass(self, func, name, bases, metaclass, kwds)

    # Print the current stack from bottom to top
    def print_stack(self):
        i = len(self.stack) -1
        for el in reversed(self.stack):
            print("\t " + str(i) + " " + str(el))
            i -= 1

    # Push a value onto the stack
    def push(self, value):
        if self.args.execution:
            print("PUSH " + str(value) + str(value.__class__))

        self.stack.append(value)

    # Pop a value from the stack
    def pop(self):
        if self.args.execution:
            res = self.stack.pop()
            print("POP " + str(res) + str(res.__class__))
            return res
        else:
            return self.stack.pop()

    # Execute the current function
    def execute_function(self, mfunction):

        self.functions_called.append(mfunction)

        # Entry block
        self.execute_block(mfunction.start_basic_block)

    def execute_block(self, block):
        for instruction in block.instructions:
            self.execute_instruction(instruction)

    # Dispatch of instructions
    def execute_instruction(self, instruction):
        if self.args.execution:
            print("Execution of " + str(instruction))

        if isinstance(instruction, model.POP_TOP):
            self.POP_TOP(instruction)
        elif isinstance(instruction, model.ROT_TWO):
            self.ROT_TWO(instruction)
        elif isinstance(instruction, model.ROT_THREE):
            self.ROT_THREE(instruction)
        elif isinstance(instruction, model.DUP_TOP):
            self.DUP_TOP(instruction)
        elif isinstance(instruction, model.DUP_TOP_TWO):
            self.DUP_TOP_TWO(instruction)
        elif isinstance(instruction, model.NOP):
            self.NOP(instruction)
        elif isinstance(instruction, model.UNARY_POSITIVE):
            self.UNARY_POSITIVE(instruction)
        elif isinstance(instruction, model.UNARY_NEGATIVE):
            self.UNARY_NEGATIVE(instruction)
        elif isinstance(instruction, model.UNARY_NOT):
            self.UNARY_NOT(instruction)
        elif isinstance(instruction, model.UNARY_INVERT):
            self.UNARY_INVERT(instruction)
        elif isinstance(instruction, model.BINARY_MATRIX_MULTIPLY):
            self.BINARY_MATRIX_MULTIPLY(instruction)
        elif isinstance(instruction, model.INPLACE_MATRIX_MULTIPLY):
            self.INPLACE_MATRIX_MULTIPLY(instruction)
        elif isinstance(instruction, model.BINARY_POWER):
            self.BINARY_POWER(instruction)
        elif isinstance(instruction, model.BINARY_MULTIPLY):
            self.BINARY_MULTIPLY(instruction)
        elif isinstance(instruction, model.BINARY_MODULO):
            self.BINARY_MODULO(instruction)
        elif isinstance(instruction, model.BINARY_ADD):
            self.BINARY_ADD(instruction)
        elif isinstance(instruction, model.BINARY_SUBTRACT):
            self.BINARY_SUBTRACT(instruction)
        elif isinstance(instruction, model.BINARY_SUBSCR):
            self.BINARY_SUBSCR(instruction)
        elif isinstance(instruction, model.BINARY_FLOOR_DIVIDE):
            self.BINARY_FLOOR_DIVIDE(instruction)
        elif isinstance(instruction, model.BINARY_TRUE_DIVIDE):
            self.BINARY_TRUE_DIVIDE(instruction)
        elif isinstance(instruction, model.INPLACE_FLOOR_DIVIDE):
            self.INPLACE_FLOOR_DIVIDE(instruction)
        elif isinstance(instruction, model.INPLACE_TRUE_DIVIDE):
            self.INPLACE_TRUE_DIVIDE(instruction)
        elif isinstance(instruction, model.GET_AITER):
            self.GET_AITER(instruction)
        elif isinstance(instruction, model.GET_ANEXT):
            self.GET_ANEXT(instruction)
        elif isinstance(instruction, model.BEFORE_ASYNC_WITH):
            self.BEFORE_ASYNC_WITH(instruction)
        elif isinstance(instruction, model.INPLACE_ADD):
            self.INPLACE_ADD(instruction)
        elif isinstance(instruction, model.INPLACE_SUBTRACT):
            self.INPLACE_SUBTRACT(instruction)
        elif isinstance(instruction, model.INPLACE_MULTIPLY):
            self.INPLACE_MULTIPLY(instruction)
        elif isinstance(instruction, model.INPLACE_MODULO):
            self.INPLACE_MODULO(instruction)
        elif isinstance(instruction, model.STORE_SUBSCR):
            self.STORE_SUBSCR(instruction)
        elif isinstance(instruction, model.DELETE_SUBSCR):
            self.DELETE_SUBSCR(instruction)
        elif isinstance(instruction, model.BINARY_LSHIFT):
            self.BINARY_LSHIFT(instruction)
        elif isinstance(instruction, model.BINARY_RSHIFT):
            self.BINARY_RSHIFT(instruction)
        elif isinstance(instruction, model.BINARY_AND):
            self.BINARY_AND(instruction)
        elif isinstance(instruction, model.BINARY_XOR):
            self.BINARY_XOR(instruction)
        elif isinstance(instruction, model.BINARY_OR):
            self.BINARY_OR(instruction)
        elif isinstance(instruction, model.INPLACE_POWER):
            self.INPLACE_POWER(instruction)
        elif isinstance(instruction, model.GET_ITER):
            self.GET_ITER(instruction)
        elif isinstance(instruction, model.GET_YIELD_FROM_ITER):
            self.GET_YIELD_FROM_ITER(instruction)
        elif isinstance(instruction, model.PRINT_EXPR):
            self.PRINT_EXPR(instruction)
        elif isinstance(instruction, model.LOAD_BUILD_CLASS):
            self.LOAD_BUILD_CLASS(instruction)
        elif isinstance(instruction, model.YIELD_FROM):
            self.YIELD_FROM(instruction)
        elif isinstance(instruction, model.GET_AWAITABLE):
            self.GET_AWAITABLE(instruction)
        elif isinstance(instruction, model.INPLACE_LSHIFT):
            self.INPLACE_LSHIFT(instruction)
        elif isinstance(instruction, model.INPLACE_RSHIFT):
            self.INPLACE_RSHIFT(instruction)
        elif isinstance(instruction, model.INPLACE_AND):
            self.INPLACE_AND(instruction)
        elif isinstance(instruction, model.INPLACE_XOR):
            self.INPLACE_XOR(instruction)
        elif isinstance(instruction, model.INPLACE_OR):
            self.INPLACE_OR(instruction)
        elif isinstance(instruction, model.BREAK_LOOP):
            self.BREAK_LOOP(instruction)
        elif isinstance(instruction, model.WITH_CLEANUP_START):
            self.WITH_CLEANUP_START(instruction)
        elif isinstance(instruction, model.WITH_CLEANUP_FINISH):
            self.WITH_CLEANUP_FINISH(instruction)
        elif isinstance(instruction, model.RETURN_VALUE):
            self.RETURN_VALUE(instruction)
        elif isinstance(instruction, model.IMPORT_STAR):
            self.IMPORT_STAR(instruction)
        elif isinstance(instruction, model.SETUP_ANNOTATIONS):
            self.SETUP_ANNOTATIONS(instruction)
        elif isinstance(instruction, model.YIELD_VALUE):
            self.YIELD_VALUE(instruction)
        elif isinstance(instruction, model.POP_BLOCK):
            self.POP_BLOCK(instruction)
        elif isinstance(instruction, model.END_FINALLY):
            self.END_FINALLY(instruction)
        elif isinstance(instruction, model.POP_EXCEPT):
            self.POP_EXCEPT(instruction)
        elif isinstance(instruction, model.HAVE_ARGUMENT):
            self.HAVE_ARGUMENT(instruction)
        elif isinstance(instruction, model.STORE_NAME):
            self.STORE_NAME(instruction)
        elif isinstance(instruction, model.DELETE_NAME):
            self.DELETE_NAME(instruction)
        elif isinstance(instruction, model.UNPACK_SEQUENCE):
            self.UNPACK_SEQUENCE(instruction)
        elif isinstance(instruction, model.FOR_ITER):
            self.FOR_ITER(instruction)
        elif isinstance(instruction, model.UNPACK_EX):
            self.UNPACK_EX(instruction)
        elif isinstance(instruction, model.STORE_ATTR):
            self.STORE_ATTR(instruction)
        elif isinstance(instruction, model.DELETE_ATTR):
            self.DELETE_ATTR(instruction)
        elif isinstance(instruction, model.STORE_GLOBAL):
            self.STORE_GLOBAL(instruction)
        elif isinstance(instruction, model.DELETE_GLOBAL):
            self.DELETE_GLOBAL(instruction)
        elif isinstance(instruction, model.LOAD_CONST):
            self.LOAD_CONST(instruction)
        elif isinstance(instruction, model.LOAD_NAME):
            self.LOAD_NAME(instruction)
        elif isinstance(instruction, model.BUILD_TUPLE):
            self.BUILD_TUPLE(instruction)
        elif isinstance(instruction, model.BUILD_LIST):
            self.BUILD_LIST(instruction)
        elif isinstance(instruction, model.BUILD_SET):
            self.BUILD_SET(instruction)
        elif isinstance(instruction, model.BUILD_MAP):
            self.BUILD_MAP(instruction)
        elif isinstance(instruction, model.LOAD_ATTR):
            self.LOAD_ATTR(instruction)
        elif isinstance(instruction, model.COMPARE_OP):
            self.COMPARE_OP(instruction)
        elif isinstance(instruction, model.IMPORT_NAME):
            self.IMPORT_NAME(instruction)
        elif isinstance(instruction, model.IMPORT_FROM):
            self.IMPORT_FROM(instruction)
        elif isinstance(instruction, model.JUMP_FORWARD):
            self.JUMP_FORWARD(instruction)
        elif isinstance(instruction, model.JUMP_IF_FALSE_OR_POP):
            self.JUMP_IF_FALSE_OR_POP(instruction)
        elif isinstance(instruction, model.JUMP_IF_TRUE_OR_POP):
            self.JUMP_IF_TRUE_OR_POP(instruction)
        elif isinstance(instruction, model.JUMP_ABSOLUTE):
            self.JUMP_ABSOLUTE(instruction)
        elif isinstance(instruction, model.POP_JUMP_IF_FALSE):
            self.POP_JUMP_IF_FALSE(instruction)
        elif isinstance(instruction, model.POP_JUMP_IF_TRUE):
            self.POP_JUMP_IF_TRUE(instruction)
        elif isinstance(instruction, model.LOAD_GLOBAL):
            self.LOAD_GLOBAL(instruction)
        elif isinstance(instruction, model.CONTINUE_LOOP):
            self.CONTINUE_LOOP(instruction)
        elif isinstance(instruction, model.SETUP_LOOP):
            self.SETUP_LOOP(instruction)
        elif isinstance(instruction, model.SETUP_EXCEPT):
            self.SETUP_EXCEPT(instruction)
        elif isinstance(instruction, model.SETUP_FINALLY):
            self.SETUP_FINALLY(instruction)
        elif isinstance(instruction, model.LOAD_FAST):
            self.LOAD_FAST(instruction)
        elif isinstance(instruction, model.STORE_FAST):
            self.STORE_FAST(instruction)
        elif isinstance(instruction, model.DELETE_FAST):
            self.DELETE_FAST(instruction)
        elif isinstance(instruction, model.STORE_ANNOTATION):
            self.STORE_ANNOTATION(instruction)
        elif isinstance(instruction, model.RAISE_VARARGS):
            self.RAISE_VARARGS(instruction)
        elif isinstance(instruction, model.CALL_FUNCTION):
            self.CALL_FUNCTION(instruction)
        elif isinstance(instruction, model.MAKE_FUNCTION):
            self.MAKE_FUNCTION(instruction)
        elif isinstance(instruction, model.BUILD_SLICE):
            self.BUILD_SLICE(instruction)
        elif isinstance(instruction, model.LOAD_CLOSURE):
            self.LOAD_CLOSURE(instruction)
        elif isinstance(instruction, model.LOAD_DEREF):
            self.LOAD_DEREF(instruction)
        elif isinstance(instruction, model.STORE_DEREF):
            self.STORE_DEREF(instruction)
        elif isinstance(instruction, model.DELETE_DEREF):
            self.DELETE_DEREF(instruction)
        elif isinstance(instruction, model.CALL_FUNCTION_KW):
            self.CALL_FUNCTION_KW(instruction)
        elif isinstance(instruction, model.CALL_FUNCTION_EX):
            self.CALL_FUNCTION_EX(instruction)
        elif isinstance(instruction, model.SETUP_WITH):
            self.SETUP_WITH(instruction)
        elif isinstance(instruction, model.EXTENDED_ARG):
            self.EXTENDED_ARG(instruction)
        elif isinstance(instruction, model.LIST_APPEND):
            self.LIST_APPEND(instruction)
        elif isinstance(instruction, model.SET_ADD):
            self.SET_ADD(instruction)
        elif isinstance(instruction, model.MAP_ADD):
            self.MAP_ADD(instruction)
        elif isinstance(instruction, model.LOAD_CLASSDEREF):
            self.LOAD_CLASSDEREF(instruction)
        elif isinstance(instruction, model.BUILD_LIST_UNPACK):
            self.BUILD_LIST_UNPACK(instruction)
        elif isinstance(instruction, model.BUILD_MAP_UNPACK):
            self.BUILD_MAP_UNPACK(instruction)
        elif isinstance(instruction, model.BUILD_MAP_UNPACK_WITH_CALL):
            self.BUILD_MAP_UNPACK_WITH_CALL(instruction)
        elif isinstance(instruction, model.BUILD_TUPLE_UNPACK):
            self.BUILD_TUPLE_UNPACK(instruction)
        elif isinstance(instruction, model.BUILD_SET_UNPACK):
            self.BUILD_SET_UNPACK(instruction)
        elif isinstance(instruction, model.SETUP_ASYNC_WITH):
            self.SETUP_ASYNC_WITH(instruction)
        elif isinstance(instruction, model.FORMAT_VALUE):
            self.FORMAT_VALUE(instruction)
        elif isinstance(instruction, model.BUILD_CONST_KEY_MAP):
            self.BUILD_CONST_KEY_MAP(instruction)
        elif isinstance(instruction, model.BUILD_STRING):
            self.BUILD_STRING(instruction)
        elif isinstance(instruction, model.BUILD_TUPLE_UNPACK_WITH_CALL):
            self.BUILD_TUPLE_UNPACK_WITH_CALL(instruction)

    def POP_TOP(self, instruction):
        self.pop()

    def ROT_TWO(self, instruction):
        first = self.pop()
        second = self.pop()

        self.push(first)
        self.push(second)

    def ROT_THREE(self, instruction): print("NYI " + str(self))

    def DUP_TOP(self, instruction): print("NYI " + str(self))

    def DUP_TOP_TWO(self, instruction): print("NYI " + str(self))

    def NOP(self, instruction): print("NYI " + str(self))

    def UNARY_POSITIVE(self, instruction): print("NYI " + str(self))

    def UNARY_NEGATIVE(self, instruction): print("NYI " + str(self))

    def UNARY_NOT(self, instruction): print("NYI " + str(self))

    def UNARY_INVERT(self, instruction): print("NYI " + str(self))

    def BINARY_MATRIX_MULTIPLY(self, instruction): print("NYI " + str(self))

    def INPLACE_MATRIX_MULTIPLY(self, instruction): print("NYI " + str(self))

    def BINARY_POWER(self, instruction):
        tos = self.pop()
        tos1 = self.pop()

        val = pow(tos1, tos)
        self.push(val)

    def BINARY_MULTIPLY(self, instruction):
        tos = self.pop()
        tos1 = self.pop()

        val = tos1 * tos
        self.push(val)

    def BINARY_MODULO(self, instruction):
        tos = self.pop()
        tos1 = self.pop()

        val = tos1 % tos
        self.push(val)

    def BINARY_ADD(self, instruction):
        tos = self.pop()
        tos1 = self.pop()

        val = tos1 + tos
        self.push(val)

    def BINARY_SUBTRACT(self, instruction):
        tos = self.pop()
        tos1 = self.pop()

        val = tos1 - tos
        self.push(val)

    def BINARY_SUBSCR(self, instruction):
        tos = self.pop()
        tos1 = self.pop()

        val = tos1[tos]
        self.push(val)

    def BINARY_FLOOR_DIVIDE(self):
        tos = self.pop()
        tos1 = self.pop()

        val = tos1 // tos
        self.push(val)

    def BINARY_TRUE_DIVIDE(self):
        tos = self.pop()
        tos1 = self.pop()

        val = tos1 / tos
        self.push(val)

    def INPLACE_FLOOR_DIVIDE(self, instruction): print("NYI " + str(self))

    def INPLACE_TRUE_DIVIDE(self, instruction): print("NYI " + str(self))

    def GET_AITER(self, instruction): print("NYI " + str(self))

    def GET_ANEXT(self, instruction): print("NYI " + str(self))

    def BEFORE_ASYNC_WITH(self, instruction): print("NYI " + str(self))

    def INPLACE_ADD(self, instruction):
        second = self.pop()
        first = self.pop()

        self.push(first + second)

    def INPLACE_SUBTRACT(self, instruction): print("NYI " + str(self))

    def INPLACE_MULTIPLY(self, instruction):
        second = self.pop()
        first = self.pop()

        self.push(first * second)

    def INPLACE_MODULO(self, instruction): print("NYI " + str(self))

    def STORE_SUBSCR(self, instruction): print("NYI " + str(self))

    def DELETE_SUBSCR(self, instruction): print("NYI " + str(self))

    def BINARY_LSHIFT(self, instruction): print("NYI " + str(self))

    def BINARY_RSHIFT(self, instruction): print("NYI " + str(self))

    def BINARY_AND(self, instruction): print("NYI " + str(self))

    def BINARY_XOR(self, instruction): print("NYI " + str(self))

    def BINARY_OR(self, instruction): print("NYI " + str(self))

    def INPLACE_POWER(self, instruction): print("NYI " + str(self))

    def GET_ITER(self, instruction):
        # Create an iterator from the TOS object and push it on the stack
        tos = self.pop()
        self.push(iter(tos))

    def GET_YIELD_FROM_ITER(self, instruction): print("NYI " + str(self))

    def PRINT_EXPR(self, instruction): print("NYI " + str(self))

    def LOAD_BUILD_CLASS(self, instruction):
        # Push the function which will make the class
        self.push(self.make_class)

    def YIELD_FROM(self, instruction): print("NYI " + str(self))

    def GET_AWAITABLE(self, instruction): print("NYI " + str(self))

    def INPLACE_LSHIFT(self, instruction): print("NYI " + str(self))

    def INPLACE_RSHIFT(self, instruction): print("NYI " + str(self))

    def INPLACE_AND(self, instruction): print("NYI " + str(self))

    def INPLACE_XOR(self, instruction): print("NYI " + str(self))

    def INPLACE_OR(self, instruction): print("NYI " + str(self))

    def BREAK_LOOP(self, instruction): print("NYI " + str(self))

    def WITH_CLEANUP_START(self, instruction): print("NYI " + str(self))

    def WITH_CLEANUP_FINISH(self, instruction): print("NYI " + str(self))

    def RETURN_VALUE(self, instruction):
        tos = self.pop()

        # Reset the environment of the call
        self.current_function().environments.pop()
        self.environments.pop()
        self.functions_called.pop()

        # Push again the result
        self.push(tos)

    def IMPORT_STAR(self, instruction): print("NYI " + str(self))

    def SETUP_ANNOTATIONS(self, instruction): print("NYI " + str(self))

    def YIELD_VALUE(self, instruction):
        #TODO
        self.print_stack()
        tos = self.pop()

        print("TOS of a YIELD " + str(tos))
        print("Class of TOS " + str(tos.__class__))
        print("Instructions in block " + str(self.block.instructions))

        self.current_function().environments.pop()
        self.environments.pop()
        self.functions_called.pop()

        self.push(tos)

    def POP_BLOCK(self, instruction):
        # In the current model, this instruction is already handled
        pass

    def END_FINALLY(self, instruction): print("NYI " + str(self))

    def POP_EXCEPT(self, instruction): print("NYI " + str(self))

    def HAVE_ARGUMENT(self, instruction): print("NYI " + str(self))

    def STORE_NAME(self, instruction):
        tos = self.pop()
        name = self.current_function().names[instruction.arguments]

        # If tos is the main function of a class, we are in fact
        # adding a property to this class here, special treatment
        if self.current_function().is_class:
            self.current_function().mclass.add_attribute(name, tos)

        # # If we are in the top level of the program
        if instruction.function.is_main and instruction.function.name == "main":
            # also make a global store
            self.global_environment[name] = tos

        self.current_function().environments[-1][name] = tos

    def DELETE_NAME(self, instruction): print("NYI " + str(self))

    def UNPACK_SEQUENCE(self, instruction):
        # Unpack tuple items and push them on the stack right to left
        tos = self.pop()
        for item in reversed(tos):
            self.push(item)

    def FOR_ITER(self, instruction):
        # TOS is an iterator
        tos = self.pop()

        need_jump = False

        # Try to get a value from the iterator
        try:
            value = tos.__next__()

            # Push back the iterator and the yield value
            self.push(tos)
            self.push(value)
        except StopIteration:
            # If it is exhausted, make a jump
            need_jump = True

        # Find the next block depending of the iterator
        for block in self.block.next:
            if block.instructions[0].offset == instruction.absolute_target:
                # Make the jump
                jump_block = block
            else:
                # Continue
                notjump_block = block

        if need_jump:
            self.execute_block(jump_block)
        else:
            self.execute_block(notjump_block)

    def UNPACK_EX(self, instruction): print("NYI " + str(self))

    def STORE_ATTR(self, instruction):
        # Get the attribute and the value and set it
        obj = self.pop()
        value = self.pop()
        name = self.current_function().names[instruction.arguments]

        obj.set_attribute(name, value)

        self.push(value)

    def DELETE_ATTR(self, instruction): print("NYI " + str(self))

    def STORE_GLOBAL(self, instruction): print("NYI " + str(self))

    def DELETE_GLOBAL(self, instruction): print("NYI " + str(self))

    def LOAD_CONST(self, instruction):
        loaded_value = self.current_function().consts[instruction.arguments]
        self.push(loaded_value)

        # If we load a Code Object, disassemble it
        if isinstance(loaded_value, CodeType):
            if self.args.verbose:
                dis.dis(loaded_value)

    def LOAD_NAME(self, instruction):
        name = str(self.current_function().names[instruction.arguments])

        # try to find the name in local environments
        if name in self.current_function().environments[-1]:
            self.push(self.current_function().environments[-1][name])
        else:
            # Lookup in the global environment
            self.push(self.global_environment[name])

    def BUILD_TUPLE(self, instruction):
        res = []
        for i in range(0, instruction.arguments):
            res.append(self.pop())

        res.reverse()
        self.push(tuple(res))

    def BUILD_LIST(self, instruction):
        res = []
        for i in range(0, instruction.arguments):
            res.append(self.pop())
        res.reverse()

        self.push(res)

    def BUILD_SET(self, instruction):
        res = set()
        for i in range(0, instruction.arguments):
            res.add(self.pop())

        self.push(res)

    def BUILD_MAP(self, instruction): print("NYI " + str(self))

    def LOAD_ATTR(self, instruction):
        tos = self.pop()
        name = self.current_function().names[instruction.arguments]

        # Lookup a name in a python module object
        if isinstance(tos, model.MModule):
            # Special case for a Module
            fun = tos.lookup(name, False)
            self.push(fun)
        elif isinstance(tos, model.MObject):
            # Access to an attribute of the model
            res = tos.get_property(name)

            # Two cases here, we accessed to a method or an attribute value
            if isinstance(res, model.Function):
                # If it's a function, we will make a method called later
                # Set the object at the receiver of the method for later
                res.receiver = tos

            self.push(res)
        else:
            # Access to an attribute
            attr = getattr(tos, name)
            self.push(attr)

    def COMPARE_OP(self, instruction):
        second = self.pop()
        first = self.pop()

        # Perform the test and push the result on the stack
        res = compare_functions[instruction.arguments](first, second)
        self.push(res)

    def IMPORT_NAME(self, instruction):
        module_name = self.current_function().names[instruction.arguments]
        from_list = self.pop()
        level = self.pop()

        # Add the subdirectory to the path to import
        module_name = self.subdirectory + "." + module_name

        # Find the module file
        spec = importlib.util.find_spec(module_name)

        # Create a module without executing it
        pythonmodule = importlib.util.module_from_spec(spec)

        # Now we need to execute this module, start by compiling it
        co = frontend.compiler.compile_import(pythonmodule.__file__, self.args)

        module = model.MModule(co)
        self.modules.append(module)

        # Generate a function for the module
        fun = self.generate_function(co, self.current_function().names[instruction.arguments], module, True)

        env = {}
        self.environments.append(env)
        fun.environments.append(env)

        self.execute_function(fun)

        self.push(module)

    def IMPORT_FROM(self, instruction): print("NYI " + str(self))

    def JUMP_FORWARD(self, instruction):
        for block in self.block.next:
            if block.instructions[0].offset == instruction.absolute_target:
                self.execute_block(block)
                return

    def JUMP_IF_FALSE_OR_POP(self, instruction):
        value = self.pop()
        jump_block = None
        notjump_block = None

        # Locate the target of the jump in next basic blocks
        for block in self.block.next:
            # If we need to make the jump
            if block.instructions[0].offset == instruction.arguments:
                jump_block = block
            else:
                # Continue the execution in the second block
                notjump_block = block

        if not value:
            self.push(value)
            self.execute_block(jump_block)
        else:
            self.execute_block(notjump_block)

    def JUMP_IF_TRUE_OR_POP(self, instruction):
        value = self.pop()
        jump_block = None
        notjump_block = None

        # Locate the target of the jump in next basic blocks
        for block in self.block.next:
            # If we need to make the jump
            if block.instructions[0].offset == instruction.arguments:
                jump_block = block
            else:
                # Continue the execution in the second block
                notjump_block = block

        if value:
            self.push(value)
            self.execute_block(jump_block)
        else:
            self.execute_block(notjump_block)

    def JUMP_ABSOLUTE(self, instruction):
        for block in self.block.next:
            # Make the jump
            if block.instructions[0].offset == instruction.arguments:
                self.execute_block(block)
                return
        # TODO: We should have jump before, put an assertion here

    def POP_JUMP_IF_FALSE(self, instruction):
        value = self.pop()
        jump_block = None
        notjump_block = None

        # Locate the target of the jump in next basic blocks
        for block in self.block.next:
            # If we need to make the jump
            if block.instructions[0].offset == instruction.arguments:
                jump_block = block
            else:
                # Continue the execution in the second block
                notjump_block = block

        if not value:
            self.execute_block(jump_block)
        else:
            self.execute_block(notjump_block)

    def POP_JUMP_IF_TRUE(self, instruction):
        value = self.pop()
        jump_block = None
        notjump_block = None

        # Locate the target of the jump in next basic blocks
        for block in self.block.next:
            # If we need to make the jump
            if block.instructions[0].offset == instruction.arguments:
                jump_block = block
            else:
                # Continue the execution in the second block
                notjump_block = block

        if value:
            self.execute_block(jump_block)
        else:
            self.execute_block(notjump_block)

    def LOAD_GLOBAL(self, instruction):
        name = self.current_function().names[instruction.arguments]

        # Lookup in the global environment
        if name in self.global_environment:
            self.push(self.global_environment[name])
        else:
            # Lookup in its module to find a name
            self.push(self.function.module.lookup(name, False))

    def CONTINUE_LOOP(self, instruction): print("NYI " + str(self))

    def SETUP_LOOP(self, instruction):
        # For now, do nothing, the end of the loop wild discard the block
        pass

    def SETUP_EXCEPT(self, instruction): print("NYI " + str(self))

    def SETUP_FINALLY(self, instruction): print("NYI " + str(self))

    def LOAD_FAST(self, instruction):
        varname = self.current_function().varnames[instruction.arguments]
        for env in reversed(self.current_function().environments):
            if varname in env:
                self.push(env[varname])
                return

    def LOAD_FAST(self, instruction):
        value = self.pop()
        varname = self.current_function().varnames[instruction.arguments]

        self.current_function().environments[-1][varname] = value

    def DELETE_FAST(self, instruction): print("NYI " + str(self))

    def STORE_ANNOTATION(self, instruction): print("NYI " + str(self))

    def RAISE_VARARGS(self, instruction): print("NYI " + str(self))

    #TODO: factorize with other call functions
    def CALL_FUNCTION(self, instruction):
        # Default arguments
        args = []
        for i in range(0, instruction.arguments):
            # Pop all arguments of the call and put them in environment
            args.append(self.pop())

        # Put arguments in right order
        args.reverse()

        # Creating an empty environment
        env = {}

        # TOS is now the function to call
        function = self.pop()
        if isinstance(function, model.MClass):
            # We have to make a new instance of a class
            self.push(function.new_instance_interpreter(args))
            return
        elif isinstance(function, model.Function):
            args_call = len(args)
            args_function = function.argcount

            if args_call < args_function:
                # We are doing a method call here, add self parameter
                # this parameter must be set before
                args.insert(0, function.receiver)
        else:
            # Special case of a call to a primitive function
            self.push(function(*args))
            return

        function.environments.append(env)
        self.environments.append(env)

        # Initialize the environment for the function call
        for i in range(0, len(args)):
            if not len(function.varnames) == 0:
                env[function.varnames[i]] = args[i]

        # Make the call
        self.execute_function(function)

    def MAKE_FUNCTION(self, instruction):
        function_name = self.pop()
        code = self.pop()

        #TODO
        free_variables = None
        if (instruction.arguments & 8) == 8:
            # Making a closure, tuple of free variables
            free_variables = self.pop()

        if (instruction.arguments & 4) == 4:
            # Annotation dictionnary
            annotations = self.pop()

        if (instruction.arguments & 2) == 2:
            # keyword only default arguments
            keyword_only = self.pop()

        if (instruction.arguments & 1) == 1:
            # default arguments
            default = self.pop()

        # Generate a new Function Object
        # TODO: check the module of the function
        fun = self.generate_function(code, function_name, self.modules[-1], False)

        # Fill the closure
        if free_variables != None:
            for value in free_variables:
                for env in reversed(self.current_function().environments):
                    if value in env:
                        fun.closure[value] = env[value]

        # Push the Function object on the stack
        self.push(fun)

    def BUILD_SLICE(self, instruction): print("NYI " + str(self))

    def LOAD_CLOSURE(self, instruction):
        # Search the name of the variable
        varname = None
        if instruction.arguments < len(self.current_function().cellvars):
            varname = self.current_function().cellvars[instruction.arguments]
        else:
            i = instruction.arguments - len(self.current_function().cellvars)
            varname = self.current_function().cellvars[i]

        self.push(varname)

    def LOAD_DEREF(self, instruction):
        # TODO: Flat representation of closures
        varname = None
        if instruction.arguments < len(self.current_function().cellvars):
            varname = self.current_function().cellvars[instruction.arguments]
        else:
            varname = self.current_function().freevars[instruction.arguments]

        if varname not in self.current_function().closure:
            # Lookup in environment
            for env in reversed(self.current_function().environments):
                if varname in env:
                    self.push(env[varname])
                    return
        else:
            # Get the value in the closure
            self.push(self.current_function().closure[varname])

    def STORE_DEREF(self, instruction): print("NYI " + str(self))

    def DELETE_DEREF(self, instruction): print("NYI " + str(self))

    def CALL_FUNCTION_KW(self, instruction):

        # TOS is a tuple for keywords
        keywords_tuple = self.pop()
        print("keywords tuple " + str(keywords_tuple))
        print(len(keywords_tuple))

        # Creating an empty environment
        env = {}

        for element in keywords_tuple:
            env[element] = self.pop()

        print("env with keywords " + str(env))

        # Default arguments
        args = []
        for i in range(0, instruction.arguments - len(keywords_tuple)):
            # Pop all arguments of the call and put them in environment
            args.append(self.pop())

        # Put positionnal arguments in right order
        args.reverse()

        # TOS is now the function to call
        function = self.pop()
        if not isinstance(function, model.Function):
            # Special case of a call to a primitive function
            self.push(function(*args))
            return

        # Initialize the environment for the function call
        for i in range(0, len(args)):
            env[function.varnames[i]] = args[i]

        function.environments.append(env)
        self.environments.append(env)

        # Make the call
        function.execute(self)

    def CALL_FUNCTION_EX(self, instruction): print("NYI " + str(self))

    def SETUP_WITH(self, instruction): print("NYI " + str(self))

    def EXTENDED_ARG(self, instruction): print("NYI " + str(self))

    def LIST_APPEND(self, instruction):
        tos = self.pop()
        list.append(self.stack[-instruction.arguments], tos)

    def SET_ADD(self, instruction): print("NYI " + str(self))

    def MAP_ADD(self, instruction): print("NYI " + str(self))

    def LOAD_CLASSDEREF(self, instruction): print("NYI " + str(self))

    def BUILD_LIST_UNPACK(self, instruction): print("NYI " + str(self))

    def BUILD_MAP_UNPACK(self, instruction): print("NYI " + str(self))

    def BUILD_MAP_UNPACK_WITH_CALL(self, instruction): print("NYI " + str(self))

    def BUILD_TUPLE_UNPACK(self, instruction): print("NYI " + str(self))

    def BUILD_SET_UNPACK(self, instruction): print("NYI " + str(self))

    def SETUP_ASYNC_WITH(self, instruction): print("NYI " + str(self))

    def FORMAT_VALUE(self, instruction): print("NYI " + str(self))

    def BUILD_CONST_KEY_MAP(self, instruction): print("NYI " + str(self))

    def BUILD_STRING(self, instruction): print("NYI " + str(self))

    def BUILD_TUPLE_UNPACK_WITH_CALL(self): print("NYI " + str(self))


def op_lesser(first, second):
    return first < second


def op_lesser_eq(first, second):
    return first <= second


def op_eq(first, second):
    return first == second


def op_noteq(first, second):
    return first != second


def op_greater(first, second):
    return first > second


def op_greater_eq(first, second):
    return first >= second


def op_in(first, second):
    return first in second


def op_notin(first, second):
    return first not in second


def op_is(first, second):
    return first is second


def op_notis(first, second):
    return not (first is second)


# TODO
def op_exception_match(first, second):
    print("NYI")
    quit()


# TODO
def op_bad(first, second):
    print("NYI")
    quit()


compare_functions = (op_lesser, op_lesser_eq, op_eq, op_noteq, op_greater,
op_greater_eq, op_in, op_notin, op_is, op_notis, op_exception_match, op_bad)


# Dictionary between names and primitive functions
primitives = {
"abs" : abs,
"dict" : dict,
"help" : help,
"min" : min,
"setattr" : setattr,
"all" : all,
"dir" : dir,
"hex" : hex,
"next" : next,
"slice" : slice,
"any" : any,
"divmod" : divmod,
"id" : id,
"object" : object,
"sorted" : sorted,
"ascii" : ascii,
"enumerate" : enumerate,
"input" : input,
"oct" : oct,
"staticmethod" : staticmethod,
"bin" : bin,
"eval" : eval,
"int" : int,
"open" : open,
"str" : str,
"bool" : bool,
"exec" : exec,
"isinstance" : isinstance,
"ord" : ord,
"sum" : sum,
"bytearray" : bytearray,
"filter" : filter,
"issubclass" : issubclass,
"pow" : pow,
"super" : super,
"bytes" : bytes,
"float" : float,
"iter" : iter,
"print" : print,
"tuple" : tuple,
"callable" : callable,
"format" : format,
"len" : len,
"property" : property,
"type" : type,
"chr" : chr,
"frozenset" : frozenset,
"list" : list,
"range" : range,
"vars" : vars,
"classmethod" : classmethod,
"getattr" : getattr,
"locals" : locals,
"repr" : repr,
"zip" : zip,
"globals" : globals,
"map" : map,
"reversed" : reversed,
"__import__" : __import__,
"complex" : complex,
"hasattr" : hasattr,
"max" : max,
"round" : round,
"hash" : hash,
"delattr" : delattr,
"memoryview" : memoryview,
"set" : set,
}
