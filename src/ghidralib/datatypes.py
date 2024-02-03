import typing
from typing import Dict, Callable
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

import ghidra
from ghidra.program.model.data import *

import varlib
from varlib import datatype

def _abstract_float_to_varlib(gdt:AbstractFloatDataType, length:int, typedef_name:str=None):
    name = typedef_name if typedef_name else gdt.name
    return datatype.BuiltinType(name, floating_point=True, signed=True, size=gdt.length)

def _abstract_int_to_varlib(gdt:AbstractIntegerDataType, length:int, typedef_name:str=None):
    name = typedef_name if typedef_name else gdt.name
    return datatype.BuiltinType(name, False, gdt.signed, gdt.length)

def _array_to_varlib(gdt:Array, length:int, typedef_name:str=None):
    return datatype.ArrayType(to_varlib_dtype(gdt.dataType, length), gdt.numElements)

def _bitfield_to_varlib(gdt:BitFieldDataType, length:int, typedef_name:str=None):
    # we don't recover bitfields, so map these to integers of matching size
    return datatype.BuiltinType(gdt.name, floating_point=False, signed=True, size=gdt.storageSize)

def _default_to_varlib(gdt:DefaultDataType, length:int, typedef_name:str=None):
    name = typedef_name if typedef_name else gdt.name
    return datatype.BuiltinType(name, False, False, gdt.length)

def _enum_to_varlib(gdt:Enum, length:int, typedef_name:str=None):
    return datatype.EnumType(gdt.getName(), gdt.getLength())

def _func_to_varlib(gdt:FunctionDefinition, length:int, typedef_name:str=None):
    return datatype.FunctionType(
            return_dtype=to_varlib_dtype(gdt.getReturnType(), gdt.getReturnType().getLength()),
            params=[to_varlib_dtype(x.getDataType(), x.getLength()) for x in gdt.getArguments()],
            name=gdt.getName()
        )

def _pointer_to_varlib(gdt:Pointer, length:int, typedef_name:str=None):
    return datatype.PointerType(to_varlib_dtype(gdt.dataType, length, typedef_name), gdt.length)

def _stringdt_to_varlib(gdt:StringDataType, length:int, typedef_name:str=None):
    if not isinstance(gdt.getReplacementBaseType(), CharDataType):
        raise Exception(f'Unhandled string replacement type {gdt.getReplacementBaseType()}')
    return datatype.ArrayType(datatype.BuiltinType('char', False, True, 1), length)

def _struct_to_varlib(gdt:Structure, length:int, typedef_name:str=None):
    # WOW...Ghidra uses multiple ids...thanks...
    sid = gdt.key   # this matches the ids we export from decompiler
    return datatype.StructType(db=None, sid=sid, name=gdt.name)

def _typedef_to_varlib(gdt:TypeDef, length:int, typedef_name:str=None):
    return to_varlib_dtype(gdt.baseDataType, length, gdt.name)

def _undefined_to_varlib(gdt:Undefined, length:int, typedef_name:str=None):
    name = typedef_name if typedef_name else gdt.name
    return datatype.BuiltinType(name, False, False, gdt.length)

def _union_to_varlib(gdt:Union, length:int, typedef_name:str=None):
    sid = gdt.key   # this matches the ids we export from decompiler
    return datatype.UnionType(db=None, sid=sid, name=gdt.name)

def _void_to_varlib(gdt:VoidDataType, length:int, typedef_name:str=None):
    return datatype.BuiltinType.create_void_type()

# thanks ghidra, this didn't work because I can't import StructureDB and the other
# (non-public) ghidra.program.database.data types...

# _data_type_map:Dict[type, Callable[[DataType, int, str], datatype.DataType]] = {
#     AbstractFloatDataType, _abstract_float_to_varlib,
#     AbstractIntegerDataType, _abstract_int_to_varlib,
#     ...
# }

def to_varlib_dtype(gdt:DataType, length:int, typedef_name:str=None) -> datatype.DataType:
    '''
    length:         Length of this datatype (but from the variable). Required only because of Ghidra's built-in
                    String datatype (if we figure out how to get its length, this can probably go away).
    typedef_name:   Allows caller to pass along a typedef name defined for an associated variable
                    (if present) so although we compare based on canonical types, we can see the more
                    readable name it had within Ghidra.
    '''
    if isinstance(gdt, AbstractFloatDataType):
        return _abstract_float_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, AbstractIntegerDataType):
        return _abstract_int_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, Array):
        return _array_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, BitFieldDataType):
        return _bitfield_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, DefaultDataType):
        return _default_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, Enum):
        return _enum_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, FunctionDefinition):
        return _func_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, Pointer):
        return _pointer_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, StringDataType):
        return _stringdt_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, Structure):
        return _struct_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, TypeDef):
        return _typedef_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, Undefined):
        return _undefined_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, Union):
        return _union_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, VoidDataType):
        return _void_to_varlib(gdt, length, typedef_name)

    if isinstance(gdt, ghidra.app.plugin.exceptionhandlers.gcc.datatype.DwarfEncodingModeDataType):
        # types we don't care about...
        return datatype.BuiltinType.create_void_type()

    raise Exception(f'Unrecognized Ghidra datatype {gdt} ({type(gdt)})')
