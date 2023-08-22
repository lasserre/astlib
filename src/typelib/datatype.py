from typing import List

class DataTypeCategories:
    BuiltIn = 'BUILTIN'
    Pointer = 'POINTER'
    Array = 'ARRAY'
    Struct = 'STRUCT'
    Union = 'UNION'

    @staticmethod
    def as_list() -> List[str]:
        return [DataTypeCategories.BuiltIn,
                DataTypeCategories.Pointer,
                DataTypeCategories.Array,
                DataTypeCategories.Struct,
                DataTypeCategories.Union]

class DataType:
    '''
    Abstract base DataType class
    '''
    def __init__(self, category:str) -> None:
        self.category = category

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
                 is_floating_point:bool, is_signed:bool, size:int) -> None:
        super().__init__(DataTypeCategories.BuiltIn)
        self.name = name
        self.is_floating_point = is_floating_point
        self.is_signed = is_signed
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
    def __init__(self, pointed_to:DataType, pointer_size:int) -> None:
        super().__init__(DataTypeCategories.Pointer)
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
    def __init__(self, element_type:DataType, num_elements:int) -> None:
        super().__init__(DataTypeCategories.Array)
        self.element_type = element_type
        self.num_elements = num_elements

    @property
    def inner(self):
        return [self.element_type]

    @property
    def size(self):
        return self.num_elements * self.element_type.size

class StructType(DataType):
    '''
    Structure types
    '''
    def __init__(self) -> None:
        super().__init__(DataTypeCategories.Struct)

# TODO: I think unions should be treated as their own type...
# since we care so much about offsets in structure recovery,
# unions are handled quite differently since everything is at
# offset = 0.

class UnionType(DataType):
    '''
    Union types
    '''
    def __init__(self) -> None:
        super().__init__(DataTypeCategories.Union)
