from typing import List, Any, Dict

class DataTypeCategories:
    BuiltIn = 'BUILTIN'
    Pointer = 'POINTER'
    Array = 'ARRAY'
    Struct = 'STRUCT'
    Union = 'UNION'

    @staticmethod
    def get_list() -> List[str]:
        return [DataTypeCategories.BuiltIn,
                DataTypeCategories.Pointer,
                DataTypeCategories.Array,
                DataTypeCategories.Struct,
                DataTypeCategories.Union]

class DataType:
    '''
    Abstract base DataType class
    '''
    def __init__(self, category:str, parent:'DataType') -> None:
        '''
        parent: Parent data type (or None) in the data type definition tree
                to help avoid infinite cycles (for example linked list that hold
                pointers to themselves)
        '''
        self.category = category
        self.parent = parent

    @property
    def inner(self) -> List['DataType']:
        '''List of nested DataType components (mimics AST structure)'''
        raise NotImplementedError(f'inner property not implemented in {self.__class__}')

    @property
    def size(self) -> int:
        '''Size of this data type in bytes'''
        raise NotImplementedError(f'size property not implemented in {self.__class__}')

class BuiltinType(DataType):
    '''
    Built-in/primitive types like int, float, long, etc.

    void is also considered a built-in type with a size of 0
    '''
    def __init__(self, name:str,
                 floating_point:bool, signed:bool, size:int) -> None:
        super().__init__(DataTypeCategories.BuiltIn, parent=None)
        self.name = name
        self.floating_point = floating_point
        self.signed = signed
        self._size = size

    @property
    def is_void(self) -> bool:
        return self.size == 0

    @property
    def inner(self):
        return []   # we're a leaf node!

    @property
    def size(self) -> int:
        return self._size

class PointerType(DataType):
    '''
    Pointer types
    '''
    def __init__(self, pointed_to:DataType, pointer_size:int, parent:DataType) -> None:
        super().__init__(DataTypeCategories.Pointer, parent)
        self.pointed_to = pointed_to
        self.pointer_size = pointer_size

    @property
    def inner(self):
        return [self.pointed_to]

    @property
    def size(self):
        return self.pointer_size

class ArrayType(DataType):
    '''
    Array types
    '''
    def __init__(self, element_type:DataType, num_elements:int, parent:DataType) -> None:
        super().__init__(DataTypeCategories.Array, parent)
        self.element_type = element_type
        self.num_elements = num_elements

    @property
    def inner(self):
        return [self.element_type]

    @property
    def size(self):
        return self.num_elements * self.element_type.size

class StructField:
    '''
    Do we want to call these fields or members? would be good to be consistent...
    '''
    def __init__(self, dtype:DataType, name:str='') -> None:
        self.dtype = dtype
        self.name = name

class StructType(DataType):
    '''
    Structure types
    '''
    def __init__(self, fields_by_offset:Dict[int, StructField], name:str='', parent:DataType=None) -> None:
        super().__init__(DataTypeCategories.Struct, parent)
        self.fields_by_offset = fields_by_offset
        self.name = name
        self.is_recursive_def = False

class RecursiveStructType(StructType):
    '''
    This is a little hacky, but purpose is to be able to:
        1. build the data type tree that can be followed as far as we care to
        2. detect and handle recursive data structures
    '''
    def __init__(self, prev_definition:StructType, parent:DataType) -> None:
        super().__init__(prev_definition.fields_by_offset,
                         prev_definition.name, parent)
        self.prev_definition = prev_definition
        self.is_recursive_def = True

    # @property
    # def fields_by_offset(self):
    #     return self.prev_definition.fields_by_offset


# NOTE: I think unions should be treated as their own type...
# since we care so much about offsets in structure recovery,
# unions are handled quite differently since everything is at
# offset = 0.

class UnionType(DataType):
    '''
    Union types
    '''
    def __init__(self, fields:List[StructField], name:str='', parent:DataType=None) -> None:
        super().__init__(DataTypeCategories.Union, parent)
        self.fields = fields
        self.name = name
