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
    def __init__(self, category:str) -> None:
        self.category = category

    def _remap_sids(self, sid_remap:Dict[int,int]):
        '''
        Remap any StructTypes contained within this type, or do nothing if not applicable

        sid_remap: Mapping of old_sid: new_sid for each sid in the database (identity maps
                   will be used if no actual change is desired)

        Guarantees:
        - new ids are outside the range of old ids, so any observed old ids (sid_remap.keys())
          will not collide with any new ids (sid_remap.values())
        '''
        raise NotImplementedError(f'_remap_sids not implemented in {self.__class__}')

    @property
    def typename_basic(self) -> str:
        '''
        Returns a basic name representing this data type. The key here, is that it
        allows a representation of the type without full parsing of its definition
        (like function prototypes, structure definitions, etc) to facilitate
        struct matching across translation units

        There's probably a better name for this...
        '''
        raise NotImplementedError(f'NAME not implemented in {self.__class__}')

    @property
    def inner(self) -> List['DataType']:
        '''List of nested DataType components (mimics AST structure)'''
        raise NotImplementedError(f'inner property not implemented in {self.__class__}')

    @property
    def size(self) -> int:
        '''Size of this data type in bytes'''
        raise NotImplementedError(f'size property not implemented in {self.__class__}')

    @property
    def type_sequence(self) -> str:
        '''Returns the data type sequence as a CSV string'''
        raise NotImplementedError(f'type_sequence property not implemented in {self.__class__}')

_standard_floats = {
    4: 'float',
    8: 'double',
    10: 'float10',
    16: 'long double',
}

# <stdint.h>-style integer names:
_standard_unsigned_ints = {
    1: 'uint8_t',
    2: 'uint16_t',
    4: 'uint32_t',
    8: 'uint64_t',
    16: '__uint128_t',
}

_standard_signed_ints = {
    1: 'int8_t',
    2: 'int16_t',
    4: 'int32_t',
    8: 'int64_t',
    16: '__int128_t',
}

class BuiltinType(DataType):
    '''
    Built-in/primitive types like int, float, long, etc.

    void is also considered a built-in type with a size of 0
    '''
    def __init__(self, name:str,
                 floating_point:bool, signed:bool, size:int) -> None:
        super().__init__(DataTypeCategories.BuiltIn)
        self.name = name
        self.floating_point = floating_point
        self.signed = signed
        self._size = size

    def _remap_sids(self, sid_remap:Dict[int,int]):
        return  # N/A

    @property
    def standard_name(self) -> str:
        '''
        Returns a consistent name for a primitive type given its core
        properties (sign, size, isFloating), as opposed to the identifier given
        to the type by the data source (e.g. uint vs. unsigned int)

        This facilitates equality comparison using only the string name
        '''
        if self.is_void:
            return 'void'
        if self.floating_point:
            return _standard_floats[self.size] if self.size in _standard_floats else f'UNMAPPED_FLOAT_{self.size}'
        elif self.signed:
            return _standard_signed_ints[self.size] if self.size in _standard_signed_ints else f'UNMAPPED_INT_{self.size}'
        else:
            return _standard_unsigned_ints[self.size] if self.size in _standard_unsigned_ints else f'UNMAPPED_UINT_{self.size}'

    @property
    def typename_basic(self) -> str:
        return self.standard_name

    def __str__(self):
        return self.standard_name

    def __eq__(self, other, dtchain:List[str]=[]):
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

    @property
    def type_sequence(self) -> str:
        return self.standard_name

class PointerType(DataType):
    '''
    Pointer types
    '''
    def __init__(self, pointed_to:DataType, pointer_size:int) -> None:
        super().__init__(DataTypeCategories.Pointer)
        self.pointed_to = pointed_to
        self.pointer_size = pointer_size

    def _remap_sids(self, sid_remap:Dict[int,int]):
        self.pointed_to._remap_sids(sid_remap)

    @property
    def inner(self):
        return [self.pointed_to]

    @property
    def size(self):
        return self.pointer_size

    @property
    def type_sequence(self) -> str:
        return f'PTR,{self.pointed_to.type_sequence}'

    @property
    def typename_basic(self) -> str:
        return f'{self.pointed_to.typename_basic}*'

    def __str__(self):
        if self.pointed_to.category == DataTypeCategories.Function:
            # delegate entire string representation to the function prototype
            # which renders itself like a function pointer
            return str(self.pointed_to)
        return f'{self.pointed_to}*'

    def __eq__(self, other, dtchain:List[str]=[]):
        if not isinstance(other, PointerType):
            return False
        # pass the dtchain along, but we don't need to add anything to it
        return self.pointed_to.__eq__(other.pointed_to, dtchain)

    def __hash__(self):
        return hash((self.pointed_to,))

class ArrayType(DataType):
    '''
    Array types
    '''
    def __init__(self, element_type:DataType, num_elements:int) -> None:
        super().__init__(DataTypeCategories.Array)
        self.element_type = element_type
        self.num_elements = num_elements

    def _remap_sids(self, sid_remap:Dict[int,int]):
        self.element_type._remap_sids(sid_remap)

    @property
    def inner(self):
        return [self.element_type]

    @property
    def size(self):
        return self.num_elements * self.element_type.size if self.num_elements else 0

    @property
    def type_sequence(self) -> str:
        return f'ARR,{self.element_type.type_sequence}'

    @property
    def typename_basic(self) -> str:
        len_str = self.num_elements if self.num_elements else ''
        return f'{self.element_type.typename_basic}[{len_str}]'

    def __str__(self):
        len_str = self.num_elements if self.num_elements else ''
        return f'{self.element_type}[{len_str}]'

    def __eq__(self, other, dtchain:List[str]=[]):
        if not isinstance(other, ArrayType):
            return False
        # pass the dtchain along, we don't need to add anything though
        return self.num_elements == other.num_elements and \
               self.element_type.__eq__(other.element_type, dtchain)

    def __hash__(self):
        return hash((self.num_elements, self.element_type))

# NOTE: I think unions should be treated as their own type...
# since we care so much about offsets in structure recovery,
# unions are handled quite differently since everything is at
# offset = 0.

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

    def __eq__(self, other, dtchain:List[str]=[]):
        if not isinstance(other, StructField):
            return False
        # NOTE: field name is not part of the comparison, just for readability
        return self.dtype.__eq__(other.dtype, dtchain)

    def __hash__(self):
        return hash((self.dtype,))

class UnionTypeBasic(DataType):
    '''
    Fake UnionType whose only purpose is to participate in typename_basic
    '''
    def __init__(self, name:str):
        super().__init__(DataTypeCategories.Union)
        self.name = name

    @property
    def typename_basic(self) -> str:
        return self.name

class UnionType(DataType):
    '''
    Union types
    '''
    def __init__(self, fields:List[StructField], name:str='') -> None:
        super().__init__(DataTypeCategories.Union)
        self.fields = fields
        self.name = name

    def _remap_sids(self, sid_remap:Dict[int,int]):
        for f in self.fields:
            f.dtype._remap_sids(sid_remap)

    @property
    def size(self):
        return max(f.size for f in self.fields)

    @property
    def type_sequence(self) -> str:
        return 'UNION'

    @property
    def typename_basic(self) -> str:
        return self.name

    def __str__(self):
        return self.name

    def __hash__(self):
        return hash(tuple(self.fields))

    def __eq__(self, other, dtchain:List[str]=[]):
        if not isinstance(other, UnionType):
            return False

        # I believe this will work, since the set equality checks that each unique
        # field is equal and the len(fields) == len(set(fields)) check ensures we
        # don't have duplicates that are "collapsing down" within the set
        # (if so, we would need to make sure that the same duplicates exist in both
        # sets of fields)

        if len(self.fields) != len(other.fields):
            return False

        dtchain_name = f'Union_{self.name}'
        if dtchain_name in dtchain:
            return True     # we have cycled around - we are equal

        dtchain.append(dtchain_name)

        other_fieldlist = list(other.fields)
        pop_other = False
        is_equal = True
        for f in self.fields:
            for o in other_fieldlist:
                if f.__eq__(o, dtchain):
                    pop_other = True
                    break
            if pop_other:
                other_fieldlist.remove(o)
                pop_other = False
            else:
                is_equal = False
                break

        dtchain.pop()   # remove self.name
        return is_equal


class EnumType(DataType):
    def __init__(self, name:str, dt_size:int=4) -> None:
        super().__init__(DataTypeCategories.Enum)
        self.name = name
        self.dt_size = dt_size  # don't know if we need this, assume 4B int for now

    def _remap_sids(self, sid_remap:Dict[int,int]):
        return  # N/A

    @property
    def size(self):
        return self.dt_size

    @property
    def type_sequence(self) -> str:
        return 'ENUM'

    @property
    def typename_basic(self) -> str:
        return self.name

    def __str__(self):
        return self.name

    def __eq__(self, other, dtchain:List[str]=[]):
        if not isinstance(other, EnumType):
            return False

        # SIMPLE NAME COMPARISON for equality since I don't think we
        # will care about recovering enum "sets"/definitions per se
        # (it's likely we "mask" enums out as ints or something...)
        # -> if we need to differentiate, then come back and FIXME
        return self.name == other.name

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
    def __init__(self, return_dtype:DataType, params:List[DataType], name:str) -> None:
        super().__init__(DataTypeCategories.Function)
        self.return_dtype = return_dtype
        self.params = params
        self.name = name

    def _remap_sids(self, sid_remap:Dict[int,int]):
        self.return_dtype._remap_sids(sid_remap)
        for p in self.params:
            p._remap_sids(sid_remap)

    @property
    def size(self):
        return 0    # this should have a pointer parent, whose size is meaningful

    @property
    def type_sequence(self) -> str:
        return 'FUNC'

    @property
    def typename_basic(self) -> str:
        return self.name if self.name else 'FuncProto'

    def __str__(self):
        # assumes function pointer
        return f'{self.return_dtype} (*)({",".join(str(p) for p in self.params)})'

    def __eq__(self, other, dtchain:List[str]=[]):
        if not isinstance(other, FunctionPrototype):
            return False

        if self.name != other.name:
            return False

        dtchain_name = f'Funcproto_{self.name}'
        if dtchain_name in dtchain:
            return True     # we have cycled around - we are equal

        dtchain.append(dtchain_name)

        if not self.return_dtype.__eq__(other.return_dtype, dtchain):
            dtchain.pop()
            return False

        # params
        if len(self.params) != len(other.params):
            dtchain.pop()
            return False

        for i, p in enumerate(self.params):
            if not p.__eq__(other.params[i], dtchain):
                dtchain.pop()
                return False

        dtchain.pop()
        return True

    def __hash__(self):
        return hash((self.name, self.return_dtype, *self.params))