# An interpreter-only virtual machine

from types import *
import dis
import importlib

import frontend

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
        self.mainmodule = Module(maincode)

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

    # Iterate over opcodes and execute the code
    def execute(self):
        # Precompile the code by generating proper instructions and basic blocks
        self.precompile()

        # Start the execution
        self.start()

    def precompile(self):
        # Generate the main function and recursively other functions in module
        self.generate_function(self.maincode, "main", self.mainmodule)

        # TODO: use identifiers instead of names to call functions

    # code : the CodeObject of this function
    # name : Function name
    # module : the Module instance
    def generate_function(self, code, name, module):

        function = Function(self.global_id_function, code.co_argcount,
    code.co_kwonlyargcount, code.co_nlocals, code.co_stacksize, code.co_consts,
    code.co_names, code.co_varnames, code.co_freevars, code.co_cellvars,
    name, dis.get_instructions(code), self, module)

        self.functions.append(function)

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

        self.current_function().execute(self)

    # Return the function currently called, the last one on the stack
    def current_function(self):
        return self.functions_called[-1]

    # Print the current stack from bottom to top
    def print_stack(self):
        i = len(self.stack) -1
        for el in reversed(self.stack):
            print("\t " + str(i) + " " + str(el))
            i -= 1

    # Push a value onto the stack
    def push(self, value):
        if self.args.execution:
            print("PUSH " + str(value))

        self.stack.append(value)

    # Pop a value from the stack
    def pop(self):
        if self.args.execution:
            res = self.stack.pop()
            print("POP " + str(res))
            return res
        else:
            return self.stack.pop()


class Module:
    pass
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

    def lookup(self, name):
        for fun in self.functions:
            if fun.name == name:
                return fun

        assert "Function not found"

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
    '''
    def __init__(self, id_function, argcount, kwonlyargcount,
                nlocals, stacksize, consts, names, varnames, freevars,
                cellvars, name, iterator, interpreter, module):
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

        # Environments are linked for each call
        self.environments = []

        self.generate_instructions()
        self.generate_basic_blocks()

        # Dictionnary of freecells and their values
        self.closure = {}

        # Add the current function to the module
        module.add_function(self)

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
        self.start_basic_block = BasicBlock()

        # Association between jump instruction and their target
        jumps = {}

        # Current is the current block, will be fill until a branching instruction
        current = self.start_basic_block

        for i in range(0, len(self.all_instructions)):
            instruction = self.all_instructions[i]
            current.add_instruction(instruction)

            if instruction.is_branch():
                # Finish the current block and create a new one
                new_block = BasicBlock()
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

                new_block = BasicBlock()
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

    # Print the current Function and its basic blocks
    def __repr__(self):
        s = "Function " + (self.name)

        return s

    # Execute the current function
    def execute(self, interpreter):

        interpreter.functions_called.append(self)

        # Entry block
        self.start_basic_block.execute(interpreter)

class BasicBlock:
    '''
        Represent a basic block : a sequence of instructions without a jump
        until the end. Basic blocks are link together and form a graph

        self.previous = previous basic blocks
        self.next = next basic blocks
        instructions = the list of instructions in order
    '''
    def __init__(self):
        self.previous = set()
        self.next = set()
        self.instructions = []

    def add_instruction(self, instruction):
        self.instructions.append(instruction)
        instruction.block = self

    # Link the self basic block to next
    # self will be a predecessor of next
    def link_to(self, next_bb):
        self.next.add(next_bb)
        next_bb.previous.add(self)

    # Execute all instructions in this block
    def execute(self, interpreter):
        for instruction in self.instructions:
            instruction.execute(interpreter)

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

    def __repr__(self):
        s = str(self.__class__) + ", offset = " + str(self.offset)
        s += ", opcode = " + str(self.opcode_number)
        s += ", opcode_string = " + self.opcode_string
        s += ", arguments = %s" + str(self.arguments)

        return s

    # Return true if self is a branching instruction, false otherwise
    def is_branch(self):
        return isinstance(self, BranchInstruction)

    # Return true if self is a jumping instruction, false otherwise
    def is_jump(self):
        return isinstance(self, JumpInstruction)

    # Execute this instruction in interpretation mode
    def execute(self, interpreter):
        if interpreter.args.verbose :
            print("Execution of : " + str(self.__class__) + " args " + str(self.arguments) + " in " + str(self.function))

# A particular class which breaks the control flow of a basic block by branching
class BranchInstruction(Instruction):
    pass

# A Branching instruction that can change the bytecode counter either by a
# relative or an absolute offset
class JumpInstruction(BranchInstruction):
    pass

    # Compute absolute_target, the absolute target of the jump of this Instruction
    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = -1

    def __repr__(self):
        s = super().__repr__()
        s += ", absolute_target " + str(self.absolute_target)

        return s

# All instruction classes
class POP_TOP(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        interpreter.pop()

class ROT_TWO(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        first = interpreter.pop()
        second = interpreter.pop()

        interpreter.push(first)
        interpreter.push(second)

class ROT_THREE(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class DUP_TOP(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class DUP_TOP_TWO(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class NOP(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class UNARY_POSITIVE(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class UNARY_NEGATIVE(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class UNARY_NOT(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class UNARY_INVERT(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BINARY_MATRIX_MULTIPLY(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class INPLACE_MATRIX_MULTIPLY(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BINARY_POWER(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()
        tos1 = interpreter.pop()

        val = pow(tos1, tos)
        interpreter.push(val)

class BINARY_MULTIPLY(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()
        tos1 = interpreter.pop()

        val = tos1 * tos
        interpreter.push(val)

class BINARY_MODULO(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()
        tos1 = interpreter.pop()

        val = tos1 % tos
        interpreter.push(val)

class BINARY_ADD(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()
        tos1 = interpreter.pop()

        val = tos1 + tos
        interpreter.push(val)

class BINARY_SUBTRACT(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()
        tos1 = interpreter.pop()

        val = tos1 - tos
        interpreter.push(val)

class BINARY_SUBSCR(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()
        tos1 = interpreter.pop()

        val = tos1[tos]
        interpreter.push(val)

class BINARY_FLOOR_DIVIDE(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()
        tos1 = interpreter.pop()

        val = tos1 // tos
        interpreter.push(val)

class BINARY_TRUE_DIVIDE(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()
        tos1 = interpreter.pop()

        val = tos1 / tos
        interpreter.push(val)

class INPLACE_FLOOR_DIVIDE(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class INPLACE_TRUE_DIVIDE(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class GET_AITER(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class GET_ANEXT(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BEFORE_ASYNC_WITH(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class INPLACE_ADD(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        second = interpreter.pop()
        first = interpreter.pop()

        interpreter.push(first + second)

class INPLACE_SUBTRACT(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class INPLACE_MULTIPLY(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        second = interpreter.pop()
        first = interpreter.pop()

        interpreter.push(first * second)

class INPLACE_MODULO(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class STORE_SUBSCR(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class DELETE_SUBSCR(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BINARY_LSHIFT(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BINARY_RSHIFT(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BINARY_AND(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BINARY_XOR(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BINARY_OR(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class INPLACE_POWER(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class GET_ITER(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        # Create an iterator from the TOS object and push it on the stack
        tos = interpreter.pop()
        interpreter.push(iter(tos))

class GET_YIELD_FROM_ITER(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class PRINT_EXPR(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class LOAD_BUILD_CLASS(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class YIELD_FROM(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class GET_AWAITABLE(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class INPLACE_LSHIFT(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class INPLACE_RSHIFT(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class INPLACE_AND(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class INPLACE_XOR(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class INPLACE_OR(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BREAK_LOOP(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class WITH_CLEANUP_START(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class WITH_CLEANUP_FINISH(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class RETURN_VALUE(BranchInstruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()

        # Reset the environment of the call
        interpreter.current_function().environments.pop()
        interpreter.environments.pop()
        interpreter.functions_called.pop()

        # Push again the result
        interpreter.push(tos)

class IMPORT_STAR(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class SETUP_ANNOTATIONS(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class YIELD_VALUE(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        interpreter.print_stack()

        tos = interpreter.pop()
        interpreter.push(tos)
        #TODO
        quit()

class POP_BLOCK(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        # In the current model, this instruction is already handled

class END_FINALLY(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class POP_EXCEPT(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class HAVE_ARGUMENT(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class STORE_NAME(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()
        print("\n STORE_NAME "+ interpreter.current_function().names[self.arguments] + " in " + str(interpreter.current_function()))
        print(interpreter.current_function().names)

        print("store " + str(tos) + " as " + interpreter.current_function().names[self.arguments])
        interpreter.current_function().environments[-1][interpreter.current_function().names[self.arguments]] = tos

class DELETE_NAME(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class UNPACK_SEQUENCE(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        # Unpack tuple items and push them on the stack right to left
        tos = interpreter.pop()
        for item in reversed(tos):
            interpreter.push(item)

class FOR_ITER(JumpInstruction):
    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = offset + arguments + size

    def execute(self, interpreter):
        super().execute(interpreter)

        # TOS is an iterator
        tos = interpreter.pop()

        need_jump = False

        # Try to get a value from the iterator
        try:
            value = tos.__next__()

            # Push back the iterator and the yield value
            interpreter.push(tos)
            interpreter.push(value)
        except StopIteration:
            # If it is exhausted, make a jump
            need_jump = True

        # Find the next block depending of the iterator
        for block in self.block.next:
            if block.instructions[0].offset == self.absolute_target:
                # Make the jump
                jump_block = block
            else:
                # Continue
                notjump_block = block

        if need_jump:
            jump_block.execute(interpreter)
        else:
            notjump_block.execute(interpreter)

class UNPACK_EX(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class STORE_ATTR(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class DELETE_ATTR(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class STORE_GLOBAL(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class DELETE_GLOBAL(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class LOAD_CONST(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        loaded_value = interpreter.current_function().consts[self.arguments]
        interpreter.push(loaded_value)

        # If we load a Code Object, disassemble it
        if isinstance(loaded_value, CodeType):
            if interpreter.args.verbose:
                dis.dis(loaded_value)

class LOAD_NAME(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        name = str(interpreter.current_function().names[self.arguments])

        print("\n LOAD_NAME " + name + " in " + str(interpreter.current_function()))
        print("env = " + str(interpreter.current_function().environments))

        # try to find the name in local environments
        if name in interpreter.current_function().environments[-1]:
            interpreter.push(interpreter.current_function().environments[-1][name])
        else:
            # Lookup in the global environment
            interpreter.push(interpreter.global_environment[name])

class BUILD_TUPLE(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        res = []
        for i in range(0, self.arguments):
            res.append(interpreter.pop())

        res.reverse()
        interpreter.push(tuple(res))

class BUILD_LIST(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        res = []
        for i in range(0, self.arguments):
            res.append(interpreter.pop())
        res.reverse()

        interpreter.push(res)

class BUILD_SET(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        res = set()
        for i in range(0, self.arguments):
            res.add(interpreter.pop())

        interpreter.push(res)

class BUILD_MAP(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class LOAD_ATTR(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()
        name = interpreter.current_function().names[self.arguments]

        # Lookup a name in a python module object
        if isinstance(tos, Module):
            # Special case for a Module
            fun = tos.lookup(name)
            interpreter.push(fun)

            #TODO: optimizing
            interpreter.global_environment[name] = fun
        else:
            # Access to an attribute
            attr = getattr(tos, name)
            interpreter.push(attr)

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
    return not(first is second)

# TODO
def op_exception_match(first, second):
    print("NYI")
    quit()

# TODO
def op_bad(first, second):
    print("NYI")
    quit()

# Compare operators
compare_operators = ('<', '<=', '==', '!=', '>', '>=', 'in',
'not in', 'is', 'is not', 'exception match', 'BAD')

compare_functions = (op_lesser, op_lesser_eq, op_eq, op_noteq, op_greater,
op_greater_eq, op_in, op_notin, op_is, op_notis, op_exception_match, op_bad)

class COMPARE_OP(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        second = interpreter.pop()
        first = interpreter.pop()

        # Perform the test and push the result on the stack
        res = compare_functions[self.arguments](first, second)
        interpreter.push(res)

class IMPORT_NAME(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        module_name = interpreter.current_function().names[self.arguments]
        from_list = interpreter.pop()
        level = interpreter.pop()

        # Add the subdirectory to the path to import
        module_name = interpreter.subdirectory + "." + module_name

        # Find the module file
        spec = importlib.util.find_spec(module_name)

        # Create a module without executing it
        pythonmodule = importlib.util.module_from_spec(spec)

        # Now we need to execute this module, start by compiling it
        co = frontend.compiler.compile_import(pythonmodule.__file__, interpreter.args)

        module = Module(co)
        interpreter.modules.append(module)

        # Generate a function for the module
        fun = interpreter.generate_function(co, interpreter.current_function().names[self.arguments], module)

        env = {}
        interpreter.environments.append(env)
        fun.environments.append(env)

        fun.execute(interpreter)

        interpreter.push(module)

class IMPORT_FROM(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class JUMP_FORWARD(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = self.offset + arguments

class JUMP_IF_FALSE_OR_POP(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = arguments

    def execute(self, interpreter):
        super().execute(interpreter)

        value = interpreter.pop()
        jump_block = None
        notjump_block = None

        # Locate the target of the jump in next basic blocks
        for block in self.block.next:
            # If we need to make the jump
            if block.instructions[0].offset == self.arguments:
                jump_block = block
            else:
                # Continue the execution in the second block
                notjump_block = block

        if not value:
            interpreter.push(value)
            jump_block.execute(interpreter)
        else:
            notjump_block.execute(interpreter)

class JUMP_IF_TRUE_OR_POP(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = arguments

    def execute(self, interpreter):
        super().execute(interpreter)

        value = interpreter.pop()
        jump_block = None
        notjump_block = None

        # Locate the target of the jump in next basic blocks
        for block in self.block.next:
            # If we need to make the jump
            if block.instructions[0].offset == self.arguments:
                jump_block = block
            else:
                # Continue the execution in the second block
                notjump_block = block

        if value:
            interpreter.push(value)
            jump_block.execute(interpreter)
        else:
            notjump_block.execute(interpreter)

class JUMP_ABSOLUTE(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = arguments

    def execute(self, interpreter):
        super().execute(interpreter)

        for block in self.block.next:
            # Make the jump
            if block.instructions[0].offset == self.arguments:
                block.execute(interpreter)
                return

        # TODO: We should have jump before, put an assertion here

class POP_JUMP_IF_FALSE(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = arguments

    def execute(self, interpreter):
        super().execute(interpreter)

        value = interpreter.pop()
        jump_block = None
        notjump_block = None

        # Locate the target of the jump in next basic blocks
        for block in self.block.next:
            # If we need to make the jump
            if block.instructions[0].offset == self.arguments:
                jump_block = block
            else:
                # Continue the execution in the second block
                notjump_block = block

        if not value:
            jump_block.execute(interpreter)
        else:
            notjump_block.execute(interpreter)

class POP_JUMP_IF_TRUE(JumpInstruction):

    def __init__(self, offset, opcode_number, opcode_string, arguments, is_jump_target, size):
        super().__init__(offset, opcode_number, opcode_string, arguments, is_jump_target, size)

        self.absolute_target = arguments

    def execute(self, interpreter):
        super().execute(interpreter)

        value = interpreter.pop()
        jump_block = None
        notjump_block = None

        # Locate the target of the jump in next basic blocks
        for block in self.block.next:
            # If we need to make the jump
            if block.instructions[0].offset == self.arguments:
                jump_block = block
            else:
                # Continue the execution in the second block
                notjump_block = block

        if value:
            jump_block.execute(interpreter)
        else:
            notjump_block.execute(interpreter)

class LOAD_GLOBAL(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        name = interpreter.current_function().names[self.arguments]

        # Lookup in the global environment
        if name in interpreter.global_environment:
            interpreter.push(interpreter.global_environment[name])
        else:
            # FIXME: find a better solution than this
            for env in reversed(interpreter.environments):
                if name in env:
                    interpreter.push(env[name])
                    return

class CONTINUE_LOOP(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class SETUP_LOOP(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        # For now, do nothing, the end of the loop wild discard the block

class SETUP_EXCEPT(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class SETUP_FINALLY(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class LOAD_FAST(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        varname = interpreter.current_function().varnames[self.arguments]
        for env in reversed(interpreter.current_function().environments):
            if varname in env:
                interpreter.push(env[varname])
                return

class STORE_FAST(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        value = interpreter.pop()
        varname = interpreter.current_function().varnames[self.arguments]

        interpreter.current_function().environments[-1][varname] = value

class DELETE_FAST(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class STORE_ANNOTATION(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class RAISE_VARARGS(BranchInstruction):
    def execute(self, interpreter): print("NYI " + str(self))

class CALL_FUNCTION(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        # Default arguments
        args = []
        for i in range(0, self.arguments):
            # Pop all arguments of the call and put them in environment
            args.append(interpreter.pop())

        # Put arguments in right order
        args.reverse()

        # Creating an empty environment
        env = {}

        # TOS is now the function to call
        function = interpreter.pop()
        if not isinstance(function, Function):
            # Special case of a call to a primitive function
            interpreter.push(function(*args))
            return

        # Initialize the environment for the function call
        for i in range(0, len(args)):
            if not len(function.varnames) == 0:
                env[function.varnames[i]] = args[i]

        function.environments.append(env)
        interpreter.environments.append(env)

        # Make the call
        function.execute(interpreter)

class MAKE_FUNCTION(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        function_name = interpreter.pop()
        code = interpreter.pop()

        #TODO
        free_variables = None
        if (self.arguments & 8) == 8:
            # Making a closure, tuple of free variables
            free_variables = interpreter.pop()

        if (self.arguments & 4) == 4:
            # Annotation dictionnary
            annotations = interpreter.pop()

        if (self.arguments & 2) == 2:
            # keyword only default arguments
            keyword_only = interpreter.pop()

        if (self.arguments & 1) == 1:
            # default arguments
            default = interpreter.pop()

        # Generate a new Function Object
        # TODO: check the module of the function
        fun = interpreter.generate_function(code, function_name, interpreter.modules[-1])

        # Fill the closure
        if free_variables != None:
            for value in free_variables:
                for env in reversed(interpreter.current_function().environments):
                    if value in env:
                        fun.closure[value] = env[value]

        # Push the Function object on the stack
        interpreter.push(fun)

class BUILD_SLICE(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class LOAD_CLOSURE(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        # Search the name of the variable
        varname = None
        if self.arguments < len(interpreter.current_function().cellvars):
            varname = interpreter.current_function().cellvars[self.arguments]
        else:
            i = self.arguments - len(interpreter.current_function().cellvars)
            varname = interpreter.current_function().cellvars[i]

        interpreter.push(varname)

class LOAD_DEREF(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        varname = None
        if self.arguments < len(interpreter.current_function().cellvars):
            varname = interpreter.current_function().cellvars[self.arguments]
        else:
            varname = interpreter.current_function().freevars[self.arguments]

        # TODO: link closures between them
        # Get the value in the closure
        interpreter.push(interpreter.current_function().closure[varname])

class STORE_DEREF(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class DELETE_DEREF(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class CALL_FUNCTION_KW(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        # TOS is a tuple for keywords
        keywords_tuple = interpreter.pop()
        print("keywords tuple " + str(keywords_tuple))
        print(len(keywords_tuple))

        # Creating an empty environment
        env = {}

        for element in keywords_tuple:
            env[element] = interpreter.pop()

        print("env with keywords " + str(env))

        # Default arguments
        args = []
        for i in range(0, self.arguments - len(keywords_tuple)):
            # Pop all arguments of the call and put them in environment
            args.append(interpreter.pop())

        # Put positionnal arguments in right order
        args.reverse()

        # TOS is now the function to call
        function = interpreter.pop()
        if not isinstance(function, Function):
            # Special case of a call to a primitive function
            interpreter.push(function(*args))
            return

        # Initialize the environment for the function call
        for i in range(0, len(args)):
            env[function.varnames[i]] = args[i]

        function.environments.append(env)
        interpreter.environments.append(env)

        # Make the call
        function.execute(interpreter)

class CALL_FUNCTION_EX(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class SETUP_WITH(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class EXTENDED_ARG(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class LIST_APPEND(Instruction):
    def execute(self, interpreter):
        super().execute(interpreter)

        tos = interpreter.pop()
        list.append(interpreter.stack[-self.arguments], tos)

class SET_ADD(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class MAP_ADD(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class LOAD_CLASSDEREF(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BUILD_LIST_UNPACK(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BUILD_MAP_UNPACK(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BUILD_MAP_UNPACK_WITH_CALL(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BUILD_TUPLE_UNPACK(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BUILD_SET_UNPACK(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class SETUP_ASYNC_WITH(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class FORMAT_VALUE(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BUILD_CONST_KEY_MAP(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BUILD_STRING(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class BUILD_TUPLE_UNPACK_WITH_CALL(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class LOAD_METHOD(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

class CALL_METHOD(Instruction):
    def execute(self, interpreter): print("NYI " + str(self))

# Dictionnary between instruction classes and opcode numbers
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
160 : LOAD_METHOD,
161 : CALL_METHOD,
}

# Dictionnary between names and primitive functions
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
