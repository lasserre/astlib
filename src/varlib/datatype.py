from typing import List, Any, Dict

class DataTypeCategories:
    BuiltIn = 'BUILTIN'
    Pointer = 'POINTER'
    Array = 'ARRAY'
    Struct = 'STRUCT'
    Union = 'UNION'
    Enum = 'ENUM'
    Function = 'FUNCTION'

    @staticmethod
    def get_list() -> List[str]:
        return [DataTypeCategories.BuiltIn,
                DataTypeCategories.Pointer,
                DataTypeCategories.Array,
                DataTypeCategories.Struct,
                DataTypeCategories.Union,
                DataTypeCategories.Enum,
                DataTypeCategories.Function]

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

    def __str__(self):
        return self.name

    def __eq__(self, other):
        if not isinstance(other, BuiltinType):
            return False
        return self.floating_point == other.floating_point and \
            self.signed == other.signed and \
            self.size == other.size

    def __hash__(self):
        return hash((self.floating_point, self.signed, self.size))

    @staticmethod
    def create_void_type():
        '''Create a new BuiltinType instance that represents the void type'''
        return BuiltinType('void', floating_point=False, signed=False, size=0)

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

    def __str__(self):
        if self.pointed_to.category == DataTypeCategories.Function:
            # delegate entire string representation to the function prototype
            # which renders itself like a function pointer
            return str(self.pointed_to)
        return f'{self.pointed_to}*'

    def __eq__(self, other):
        if not isinstance(other, PointerType):
            return False
        return self.pointed_to == other.pointed_to

    def __hash__(self):
        return hash((self.pointed_to,))

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
        return self.num_elements * self.element_type.size if self.num_elements else 0

    def __str__(self):
        len_str = self.num_elements if self.num_elements else ''
        return f'{self.element_type}[{len_str}]'

    def __eq__(self, other):
        if not isinstance(other, ArrayType):
            return False
        return self.num_elements == other.num_elements and self.element_type == other.element_type

    def __hash__(self):
        return hash((self.num_elements, self.element_type))

class StructField:
    '''
    Do we want to call these fields or members? would be good to be consistent...
    '''
    def __init__(self, dtype:DataType, name:str='') -> None:
        self.dtype = dtype
        self.name = name

    @property
    def size(self):
        return self.dtype.size

    def __str__(self):
        return f'{self.dtype} {self.name}'

    def __eq__(self, other):
        if not isinstance(other, StructField):
            return False
        # NOTE: field name is not part of the comparison, just for readability
        return self.dtype == other.dtype

    def __hash__(self):
        return hash((self.dtype,))

class StructType(DataType):
    '''
    Structure types
    '''
    def __init__(self, fields_by_offset:Dict[int, StructField], name:str='', parent:DataType=None) -> None:
        super().__init__(DataTypeCategories.Struct, parent)
        self.fields_by_offset = fields_by_offset
        self.name = name
        self.is_recursive_def = False

    @property
    def size(self):
        return sum(f.size for f in self.fields_by_offset.values())

    def __str__(self):
        return self.name

    def __eq__(self, other):
        if not isinstance(other, StructType):
            return False
        if set(self.fields_by_offset.keys()) != set(other.fields_by_offset.keys()):
            return False    # set of member offsets don't match
        for off, field in self.fields_by_offset.items():
            if field != other.fields_by_offset[off]:
                return False
        return True

    def __hash__(self):
        return hash((*self.fields_by_offset.values()))

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

    def __eq__(self, other):
        if not isinstance(other, RecursiveStructType):
            return False
        # this may change, but for now...
        # I'm thinking we just verify we're comparing to another RecursiveStructType
        # and call it good. We only should get in this case if this is nested inside
        # a larger structure...later on we could use struct IDs to be 100% sure we're
        # pointing at the right one but for now I won't worry about it
        return True

    def __hash__(self):
        return hash((len(self.prev_definition.fields_by_offset),))

def check_recursive_struct_ref(node_name:str, parent:DataType):
    '''
    Walks up the data type tree hierarchy checking if this is a recursive structure
    definition. If so, returns a RecursiveStructType for the given node_name. If
    not, returns None (and the caller may continue creating a normal StructType
    node)
    '''
    pnode = parent
    while pnode is not None:
        if pnode.category == DataTypeCategories.Struct and pnode.name == node_name:
            return RecursiveStructType(pnode, parent)
        pnode = pnode.parent
    return None     # no recursion found

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

    @property
    def size(self):
        return max(f.size for f in self.fields)

    def __str__(self):
        return self.name

    def __hash__(self):
        return hash((*self.fields))

    def __eq__(self, other):
        if not isinstance(other, UnionType):
            return False

        # I believe this will work, since the set equality checks that each unique
        # field is equal and the len(fields) == len(set(fields)) check ensures we
        # don't have duplicates that are "collapsing down" within the set
        # (if so, we would need to make sure that the same duplicates exist in both
        # sets of fields)
        if len(self.fields) != len(set(self.fields)):
            # we have duplicates
            if len(self.fields) != len(other.fields):
                return False

            other_fieldlist = list(other.fields)
            pop_other = False
            for f in self.fields:
                for o in other_fieldlist:
                    if f == o:
                        pop_other = True
                        break
                if pop_other:
                    other_fieldlist.remove(o)
                    pop_other = False
                else:
                    return False    # went through all remaining other_fieldlist and no match
            return True     # all fields matched a field in other
        else:
            # no duplicates, simple set comparison (hopefully this is normal case)
            return set(self.fields) == set(other.fields)

class EnumType(DataType):
    def __init__(self, name:str, dt_size:int=4) -> None:
        super().__init__(DataTypeCategories.Enum, None)
        self.name = name
        self.dt_size = dt_size  # don't know if we need this, assume 4B int for now

    @property
    def size(self):
        return self.dt_size

    def __str__(self):
        return self.name

    def __eq__(self, other):
        if not isinstance(other, EnumType):
            return False

        # TODO: don't return true until we have defined enum values and can
        # actually compare
        return False

    def __hash__(self):
        return hash((self.name, self.dt_size))

    # TODO - if we really care about enums, need to extend this to
    # define the enumerated values (EnumConstantDecl from AST)

class FunctionPrototype(DataType):
    '''
    This may serve double duty - we can represent a function prototype for things
    like prototype recovery - but the main purpose is to represent the prototype
    portion of a function pointer type.
    '''
    def __init__(self, return_dtype:DataType, params:List[DataType], parent: DataType) -> None:
        super().__init__(DataTypeCategories.Function, parent)
        self.return_dtype = return_dtype
        self.params = params

    @property
    def size(self):
        return 0    # this should have a pointer parent, whose size is meaningful

    def __str__(self):
        # assumes function pointer
        return f'{self.return_dtype} (*)({",".join(str(p) for p in self.params)})'

    def __eq__(self, other):
        if not isinstance(other, FunctionPrototype):
            return False
        return self.return_dtype == other.return_dtype and set(self.params) == set(other.params)

    def __hash__(self):
        return hash((self.return_dtype, *self.params))