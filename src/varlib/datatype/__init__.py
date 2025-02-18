from .datatypes import *
from .structtype import StructType, UnionType, StructLayout, UnionLayout, StructDefinition, UnionDefinition, StructField
from .structtype import StructTypeBasic, UnionTypeBasic

def replace_arr_with_ptr(dt:DataType, pointer_size:int=8) -> DataType:
    '''
    Replace each occurrence of arrays in this data type with pointers (for retyping)
    '''
    if isinstance(dt, ArrayType):
        return PointerType(replace_arr_with_ptr(dt.element_type), pointer_size)
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

def replace_dimensionless_arrays(dt:DataType, pointer_size:int=8) -> DataType:
    '''
    Return a data type that ensures each array which appears BEFORE the
    first pointer has an array size of at least 1

    Examples:
        - int[]     -> int[1]       // ARR[],int          -> ARR[1],int
        - char[][]  -> char[1][1]   // ARR[],ARR[],char   -> ARR[1],ARR[1],char
        - int*[]    -> int*[1]      // ARR[],PTR,int      -> ARR[1],PTR,int
        - int(*)[]  -> int(*)[]     // PTR,ARR[],int      -> PTR,ARR[],int

    Once we encounter a PTR, we know PTR sizes and don't need to resolve further array sizes
    '''
    if not dt or 'ARR' not in dt.type_sequence_str:
        return dt   # nothing to do

    # 1. go front->back and fill in missing array dimensions until we reach a pointer
    # 2. reconstruct the type back->front

    found_ptr = False
    converted_sequence = []
    for x in dt.type_sequence:
        if not found_ptr and isinstance(x, ArrayType) and x.num_elements < 1:
            # we reconstruct element type on our way back
            converted_sequence.append(ArrayType(element_type=None, num_elements=1))
        else:
            converted_sequence.append(x)
            if isinstance(x, PointerType):
                found_ptr = True

    # reconstruct inside-out
    new_dt = converted_sequence.pop()     # leaf_type

    # reconstruct pointer levels inside-out
    for x in converted_sequence[::-1]:
        if isinstance(x, ArrayType):
            new_dt = ArrayType(new_dt, num_elements=x.num_elements)
        elif isinstance(x, PointerType):
            new_dt = PointerType(new_dt, pointer_size=x.pointer_size)
        else:
            raise Exception(f'Unexpected non-terminal data type {x}')

    return new_dt
