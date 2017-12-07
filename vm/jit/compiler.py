'''
This module contains the JIT compiler
'''

import peachpy

# rename for better code visibility
import peachpy.x86_64 as asm
from peachpy.common.function import active_function

from . import stub_handler
import interpreter.simple_interpreter


# Dictionary between interpreter model and peachpy compiled function
dict_functions = {}
dict_compiled_functions = {}

# Compile the function  in parameter to binary code
# return the code instance
def compile_function(function, inter):

    # TODO: for now all parameter are 64 bits integers
    arguments = []
    for i in range(function.argcount):
        name = "arg" + str(i)
        arguments.append(peachpy.Argument(peachpy.int64_t, name=name))

    # TODO: handle the return type for procedures
    code = asm.Function("asm_"+function.name, tuple(arguments), peachpy.int64_t)

    dict_functions[function] = code

    # Set the active function of peachpy
    peachpy.common.function.active_function = code

    # Create registers for each argument
    arguments_registers = []
    for i in range(len(arguments)):
        arguments_registers.append(asm.rax)
        #arguments_registers.append(asm.GeneralPurposeRegister64())

    # Mapping between variables names and memory
    function.allocations = {}

    # Arguments should be on the stack
    for i in range(function.argcount):
        instruction = asm.LOAD.ARGUMENT(arguments_registers[i], arguments[i])
        function.allocations[function.varnames[i]] = arguments_registers[i]
        code.add_instruction(instruction)

    # Start the compilation of the first basic block
    compile_instructions(code, function.start_basic_block, function.allocations)

    # TODO: just a test
    if len(arguments_registers) != 0:
        print("Peachy compiled function " + str(code))
        python_function = code.finalize(asm.abi.detect()).encode().load()
        dict_compiled_functions[function] = python_function
        print(python_function.loader.code_address)
        print("Call to the function with the parameter 5 : " + str(python_function(5)))

# Compile all instructions to binary code
# code : the asm.Function object
# block : The BasicBlock to compile
# environment : Mapping between variables names and their allocations
def compile_instructions(code, block, environment):

    if block != block.function.start_basic_block:
        array = asm.PUSH(1).encode()
        array = array + asm.RETURN().encode()

        python_function = dict_compiled_functions[block.function]

        python_function.code_segment = python_function.code_segment + array

        # Recreate a loader
        print("On passe")
        # TODO: just a test
        return array
        #code_segment = dict_compiled_functions[block.function].code_segment
        #code_segment = code_segment + ins
        #dict_compiled_functions[block.function].code_segment = code_segment

        #dict_compiled_functions[block.function].loader = peachpy.loader.Loader(len(code_segment))

    for i in range(len(block.instructions)):

        instruction = block.instructions[i]
        # big dispatch for all instructions
        if isinstance(instruction, interpreter.simple_interpreter.POP_TOP):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.ROT_TWO):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.ROT_THREE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.DUP_TOP):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.DUP_TOP_TWO):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.NOP):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.UNARY_POSITIVE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.UNARY_NEGATIVE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.UNARY_NOT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.UNARY_INVERT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MATRIX_MULTIPLY):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MATRIX_MULTIPLY):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_POWER):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MULTIPLY):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MODULO):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_ADD):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_SUBTRACT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_SUBSCR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_FLOOR_DIVIDE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_TRUE_DIVIDE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_FLOOR_DIVIDE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_TRUE_DIVIDE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.GET_AITER):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.GET_ANEXT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BEFORE_ASYNC_WITH):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_ADD):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_SUBTRACT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MULTIPLY):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MODULO):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.STORE_SUBSCR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.DELETE_SUBSCR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_LSHIFT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_RSHIFT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_AND):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_XOR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BINARY_OR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_POWER):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.GET_ITER):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.GET_YIELD_FROM_ITER):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.PRINT_EXPR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.LOAD_BUILD_CLASS):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.YIELD_FROM):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.GET_AWAITABLE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_LSHIFT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_RSHIFT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_AND):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_XOR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_OR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BREAK_LOOP):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.WITH_CLEANUP_START):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.WITH_CLEANUP_FINISH):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.RETURN_VALUE):
            code.add_instruction(asm.RETURN())
        elif isinstance(instruction, interpreter.simple_interpreter.IMPORT_STAR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.SETUP_ANNOTATIONS):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.YIELD_VALUE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.POP_BLOCK):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.END_FINALLY):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.POP_EXCEPT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.HAVE_ARGUMENT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.STORE_NAME):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.DELETE_NAME):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.UNPACK_SEQUENCE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.FOR_ITER):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.UNPACK_EX):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.STORE_ATTR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.DELETE_ATTR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.STORE_GLOBAL):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.DELETE_GLOBAL):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CONST):
            print("Instruction compiled " + str(instruction))

            # We need to perform an allocation here
            value = block.function.consts[instruction.arguments]
            allocate(value, code, environment, block.function)

            print("The value is now allocated")
        elif isinstance(instruction, interpreter.simple_interpreter.LOAD_NAME):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_TUPLE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_LIST):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SET):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.LOAD_ATTR):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.COMPARE_OP):
            print("Instruction compiled " + str(instruction))

            # COMPARE_OP can't be the last instruction of the block
            next_instruction = block.instructions[i+1]

            if isinstance(next_instruction, interpreter.simple_interpreter.JUMP_IF_FALSE_OR_POP):
                compile_cmp_JUMP_IF_FALSE_OR_POP(code, instruction, next_instruction)
            elif isinstance(next_instruction, interpreter.simple_interpreter.JUMP_IF_TRUE_OR_POP):
                compile_cmp_JUMP_IF_TRUE_OR_POP(code, instruction, next_instruction)
            elif isinstance(next_instruction, interpreter.simple_interpreter.POP_JUMP_IF_FALSE):
                compile_cmp_POP_JUMP_IF_FALSE(code, instruction, next_instruction)
            elif isinstance(next_instruction, interpreter.simple_interpreter.POP_JUMP_IF_TRUE):
                compile_cmp_POP_JUMP_IF_TRUE(code, instruction, next_instruction)
            else:
                # General case, we need to put the value on the stack
                compile_cmp(instruction)

            # We already compiled the next instruction which is a branch, the block is fully compiled now
            return
        elif isinstance(instruction, interpreter.simple_interpreter.IMPORT_NAME):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.IMPORT_FROM):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.JUMP_FORWARD):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.JUMP_IF_FALSE_OR_POP):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.JUMP_IF_TRUE_OR_POP):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.JUMP_ABSOLUTE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.POP_JUMP_IF_FALSE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.POP_JUMP_IF_TRUE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.LOAD_GLOBAL):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.CONTINUE_LOOP):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.SETUP_LOOP):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.SETUP_EXCEPT):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.SETUP_FINALLY):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.LOAD_FAST):
            print("Instruction compiled " + str(instruction))

            # Load the value and put it onto the stack
            varname = block.function.varnames[instruction.arguments]
            code.add_instruction(asm.PUSH(environment[varname]))

        elif isinstance(instruction, interpreter.simple_interpreter.STORE_FAST):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.DELETE_FAST):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.STORE_ANNOTATION):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.RAISE_VARARGS):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.MAKE_FUNCTION):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SLICE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CLOSURE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.LOAD_DEREF):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.STORE_DEREF):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.DELETE_DEREF):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION_KW):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION_EX):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.SETUP_WITH):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.EXTENDED_ARG):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.LIST_APPEND):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.SET_ADD):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.MAP_ADD):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CLASSDEREF):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_LIST_UNPACK):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP_UNPACK):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP_UNPACK_WITH_CALL):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_TUPLE_UNPACK):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SET_UNPACK):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.SETUP_ASYNC_WITH):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.FORMAT_VALUE):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_CONST_KEY_MAP):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_STRING):
            print("Instruction not compiled " + str(instruction))
        elif isinstance(instruction, interpreter.simple_interpreter.BUILD_TUPLE_UNPACK_WITH_CALL):
            print("Instruction not compiled " + str(instruction))

    # Replace the old function by the new one
    if block != block.function.start_basic_block:
        print("ET ICI")
        tt = code.finalize(asm.abi.detect())
        print("Ça marche")

        python_function = code.finalize(asm.abi.detect()).encode().load()


# Allocate a value and update the environment, this function create an instruction to store the value
# value : the value to allocate
# code : asm.Function instance
# environment : mapping between memory and variable names
# function : interpreter.Function instance
def allocate(value, code, environment, function):
    # Depending of the type of the value, do different things

    if isinstance(value, int):
        # Put the integer value on the stack
        code.add_instruction(asm.PUSH(value))

    #TODO: handle other types

# Compare operators
compare_operators = ('<', '<=', '==', '!=', '>', '>=', 'in',
'not in', 'is', 'is not', 'exception match', 'BAD')

# Dictionary between stub ids and blocks to compile
stub_dictionary = {}

# Functions used to compile a comparison then a jump after (a if)
# code : The asm.Function instance
# instruction : Current python Bytecode instruction
# next_instruction : The following instruction
def compile_cmp_POP_JUMP_IF_FALSE(code, instruction, next_instruction):
    compile_cmp_beginning(code)

    # not first < second -> first >= second
    true_label = asm.Label("true_block")
    if instruction.arguments == 0:
        false_label = asm.Label("false_block")

        # Jump to stubs
        code.add_instruction(asm.JGE(true_label))
        code.add_instruction(asm.JMP(false_label))

        # TODO: call compile_stub two times here
        asm.PUSH(5)

        # Get the two following blocks
        jump_block = None
        notjump_block = None

        # Locate the target of the jump in next basic blocks
        for block in instruction.block.next:
            # If we need to make the jump
            if block.instructions[0].offset == next_instruction.arguments:
                jump_block = block
            else:
                # Continue the execution in the second block
                notjump_block = block

        # Compile a stub for each branch
        code.add_instruction(asm.LABEL(true_label))
        stub_handler.compile_stub(code, id(jump_block))
        stub_dictionary[id(jump_block)] = jump_block

        # And update the dictionary of ids and blocks
        code.add_instruction(asm.LABEL(false_label))
        stub_handler.compile_stub(code, id(notjump_block))
        stub_dictionary[id(notjump_block)] = notjump_block

    elif instruction.arguments == 1:
        pass
    else:
        pass

def compile_cmp_beginning(code):
    # Put both operand into registers
    second_register = asm.rax
    first_register = asm.rbx
    code.add_instruction(asm.POP(second_register))
    code.add_instruction(asm.POP(first_register))
    code.add_instruction(asm.CMP(second_register, first_register))



