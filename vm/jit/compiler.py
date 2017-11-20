'''
This module contains the JIT compiler
'''

import peachpy

# rename for better code visibility
import peachpy.x86_64 as asm
from peachpy.common.function import active_function

import interpreter.simple_interpreter

# Compile the function  in parameter to binary code
# return the code instance
def compile_function(function):
    print("Compilation of function " + str(function))

    # TODO: for now all parameter are 32 bits integers
    arguments = []
    for i in range(function.argcount):
        name = "arg" + str(i)
        arguments.append(peachpy.Argument(peachpy.int32_t, name=name))

    # TODO: handle the return type for procedures
    code = asm.Function("asm_"+function.name, tuple(arguments), peachpy.int32_t)

    # Set the active function of peachpy
    peachpy.common.function.active_function = code

    # Create registers for each argument
    arguments_registers = []
    for i in range(len(arguments)):
        arguments_registers.append(asm.GeneralPurposeRegister32())

    # Mapping between variables names and memory
    allocations = {}

    # Arguments should be on the stack
    for i in range(function.argcount):
        instruction = asm.LOAD.ARGUMENT(arguments_registers[i], arguments[i])
        allocations[function.varnames[i]] = arguments_registers[i]
        code.add_instruction(instruction)

    print("Allocations of arguments " + str(allocations))

    # TODO: visit for each instruction
    compile_instructions(code, function, allocations)

    # TODO: just a test
    if len(arguments_registers) != 0:
        print("Peachy compiled function "+ str(code))
        # python_function = code.finalize(asm.abi.detect()).encode().load()
        # print(python_function)

# Compile all instructions to binary code
# code : the asm.Function object
# function : The SimpleInterpreter.Function object
# environment : Mapping betweens variables names and their allocations
def compile_instructions(code, function, environment):

    for instruction in function.start_basic_block.instructions:
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
            print("Instruction not compiled " + str(instruction))
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
            print("Instruction not compiled " + str(instruction))
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
            print("Instruction not compiled " + str(instruction))
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
            print("Instruction not compiled " + str(instruction))
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
