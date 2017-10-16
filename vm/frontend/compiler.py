# Compile python source to bytecode
import py_compile
import marshal
import dis

#TODO: properly implement the norm https://www.python.org/dev/peps/pep-3147/
# to make lazy compilation of bytecode files

# Compile a .py source file to bytecode
def compile(filename):
    # We compile to the current version of python
    bytecode_filename = py_compile.compile(filename, optimize = 0)
    return parse_file(bytecode_filename)

# Parse a python bytecode file and return the CodeObject
def parse_file(filename):
    bytecode_file = open(filename, "rb")

    # The header of a bytecode file is 12 bytes long
    magic = bytecode_file.read(4)
    timestamp = bytecode_file.read(4)
    misc = bytecode_file.read(4)

    # Then we found the marshaled code object
    body = bytecode_file.read()
    co = marshal.loads(body)

    print(dis.dis(co))
    bytecode_file.close()
    return co


def disassemble_file(dir, file, version):
    os.system('%s -m py_compile "%s"' % (version, dir + file))
    module = unwind.disassemble(dir + file + 'c')
    print(module)

    return module

    # Separate directory and file name
    dirname, filename = os.path.split(args.file)
    dirname = dirname + "/"

    module = disassemble_file(dirname, filename, version)
