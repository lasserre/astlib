import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

from ghidra.program.model.data import DataType, AbstractIntegerDataType, Structure, ArrayDataType, DefaultDataType, TypeDef
from ghidra.program.model.data import AbstractFloatDataType, PointerDataType, Undefined

import varlib
from varlib import datatype

def to_varlib_dtype(gdt:DataType, typedef_name:str=None) -> datatype.DataType:
    name = typedef_name if typedef_name else gdt.name

    if isinstance(gdt, AbstractIntegerDataType):
        return datatype.BuiltinType(name, False, gdt.signed, gdt.length)
    if isinstance(gdt, AbstractFloatDataType):
        return datatype.BuiltinType(name, floating_point=True, signed=True, size=gdt.length)
    if isinstance(gdt, Structure):
        sid = gdt.universalID.value
        return varlib.StructType(sid, name=name)
    if isinstance(gdt, ArrayDataType):
        return datatype.ArrayType(to_varlib_dtype(gdt.dataType), gdt.numElements)
    if isinstance(gdt, DefaultDataType):
        name = typedef_name if typedef_name else gdt.name
        return datatype.BuiltinType(name, False, False, gdt.length)
    if isinstance(gdt, TypeDef):
        return to_varlib_dtype(gdt.baseDataType, gdt.name)
    if isinstance(gdt, PointerDataType):
        return datatype.PointerType(to_varlib_dtype(gdt.dataType, typedef_name), gdt.length)
    if isinstance(gdt, Undefined):
        name = typedef_name if typedef_name else gdt.name
        return datatype.BuiltinType(name, False, False, gdt.length)

    msg = f'Unrecognized Ghidra datatype {gdt}'
    print(msg)
    import IPython; IPython.embed()
    raise Exception(msg)
