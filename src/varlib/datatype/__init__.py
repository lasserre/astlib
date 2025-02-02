from .datatypes import *
from .structtype import StructType, UnionType, StructLayout, UnionLayout, StructDefinition, UnionDefinition, StructField
from .structtype import StructTypeBasic, UnionTypeBasic

def replace_arr_with_ptr(dt:DataType) -> DataType:
    '''
    Replace each occurrence of arrays in this data type with pointers (for retyping)
    '''
    if isinstance(dt, ArrayType):
        return PointerType(replace_arr_with_ptr(dt.element_type), pointer_size=8)
    elif isinstance(dt, PointerType):
        return PointerType(replace_arr_with_ptr(dt.pointed_to), dt.pointer_size)
    return dt

def replace_leaf_type(dt:DataType, new_leaftype:DataType) -> DataType:
    '''
    Return a data type that replaces dt's leaf type with new_leaftype
    '''
    if isinstance(dt, PointerType):
        return PointerType(replace_leaf_type(dt.pointed_to, new_leaftype), pointer_size=dt.pointer_size)
    elif isinstance(dt, ArrayType):
        return ArrayType(replace_leaf_type(dt.element_type, new_leaftype), dt.num_elements)
    # this is the leaf type
    return new_leaftype
