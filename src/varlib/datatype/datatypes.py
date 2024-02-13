import json
from typing import List, Any, Dict
from rich.console import Console

class DataTypeCategories:
    BuiltIn = 'BUILTIN'
    Pointer = 'PTR'
    Array = 'ARR'
    Struct = 'STRUCT'
    Union = 'UNION'
    Enum = 'ENUM'
    Function = 'FUNC'

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
        self._category = category   # readonly

    @property
    def category(self) -> str:
        '''The data type category for this instance'''
        return self._category

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
    def type_sequence_str(self) -> str:
        '''Returns the data type sequence as a CSV string'''
        raise NotImplementedError(f'type_sequence_str property not implemented in {self.__class__}')

    @property
    def type_sequence(self) -> List['DataType']:
        '''Returns the data type sequence as a list of the actual types'''
        raise NotImplementedError(f'type_sequence property not implemented in {self.__class__}')

    def to_dict(self) -> dict:
        '''Converts the data type into a serializable dict'''
        raise NotImplementedError(f'to_dict not implemented in {self.__class__.__name__}')

    def _get_base_dict(self) -> dict:
        return {
            'kind': str(self.__class__.__name__)
        }

class Type(DataType):
    '''
    Sometimes when the AST export code cannot resolve a type, we may
    get datatype instances of Type in the JSON export.

    This is just to wrap those instances and allow us to detect and
    filter them out downstream
    '''
    def __init__(self, name:str) -> None:
        super().__init__('Type')
        self.name = name

    @property
    def typename_basic(self) -> str:
        return 'Type'

    @property
    def inner(self):
        return []

    @property
    def size(self):
        return 0

    @property
    def to_dict(self) -> dict:
        return {
            **self._get_base_dict(),
            'name': self.name,
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'BuiltinType':
        return Type(d['name'])

_standard_floats_by_size = {
    4: 'float',
    8: 'double',
    10: 'long double',
    # 16: '',
}

_standard_uints_by_size = {
    1: 'uchar',
    2: 'ushort',
    4: 'uint32',
    8: 'uint64',
    16: 'uint128',
}

_standard_ints_by_size = {
    1: 'char',
    2: 'short',
    4: 'int32',
    8: 'int64',
    16: 'int128',
}

_standard_floats_by_name = {nm: sz for sz, nm in _standard_floats_by_size.items()}
_standard_uints_by_name = {nm: sz for sz, nm in _standard_uints_by_size.items()}
_standard_ints_by_name = {nm: sz for sz, nm in _standard_ints_by_size.items()}

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
            return _standard_floats_by_size[self.size] if self.size in _standard_floats_by_size else f'UNMAPPED_FLOAT_{self.size}'
        elif self.signed:
            return _standard_ints_by_size[self.size] if self.size in _standard_ints_by_size else f'UNMAPPED_INT_{self.size}'
        else:
            return _standard_uints_by_size[self.size] if self.size in _standard_uints_by_size else f'UNMAPPED_UINT_{self.size}'

    @property
    def typename_basic(self) -> str:
        return self.standard_name

    def __str__(self):
        return self.standard_name

    def __eq__(self, other, dtchain:List[str]=None):
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
    def type_sequence_str(self) -> str:
        return self.standard_name

    @property
    def type_sequence(self) -> List['DataType']:
        return [self]

    def to_dict(self) -> dict:
        return {
            **self._get_base_dict(),
            'name': self.name,
            'is_fp': self.floating_point,
            'signed': self.signed,
            'size': self.size
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'BuiltinType':
        return BuiltinType(name=d['name'], floating_point=d['is_fp'], signed=d['signed'], size=d['size'])

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

    @property
    def type_sequence_str(self) -> str:
        return f'{self.category},{self.pointed_to.type_sequence_str}'

    @property
    def type_sequence(self) -> List['DataType']:
        return [self, *self.pointed_to.type_sequence]

    @property
    def typename_basic(self) -> str:
        return f'{self.pointed_to.typename_basic}*'

    def __str__(self):
        if self.pointed_to.category == DataTypeCategories.Function:
            # delegate entire string representation to the function prototype
            # which renders itself like a function pointer
            return str(self.pointed_to)
        return f'{self.pointed_to}*'

    def __eq__(self, other, dtchain:List[str]=None):
        if not isinstance(other, PointerType):
            return False
        # pass the dtchain along, but we don't need to add anything to it
        return self.pointed_to.__eq__(other.pointed_to, dtchain)

    def __hash__(self):
        return hash((self.pointed_to,))

    def to_dict(self) -> dict:
        return {
            **self._get_base_dict(),
            'size': self.pointer_size,
            'inner': [self.pointed_to.to_dict()],
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'PointerType':
        return PointerType(datatype_from_dict(d['inner'][0], sdb), d['size'])

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
        return self.num_elements * self.element_type.size if self.num_elements else 0

    @property
    def type_sequence_str(self) -> str:
        return f'{self.category},{self.element_type.type_sequence_str}'

    @property
    def type_sequence(self) -> List['DataType']:
        return [self, *self.element_type.type_sequence]

    @property
    def typename_basic(self) -> str:
        len_str = self.num_elements if self.num_elements else ''
        return f'{self.element_type.typename_basic}[{len_str}]'

    def __str__(self):
        len_str = self.num_elements if self.num_elements else ''
        if isinstance(self.element_type, ArrayType):
            # {self.element_type}[self_dim][child_dim][...]
            nested = self.element_type
            dim_sizes = [self.num_elements]     # we want top->bottom going L->R
            while isinstance(nested, ArrayType):
                dim_sizes.append(nested.num_elements)
                nested = nested.element_type
            return f'{nested}[{"][".join(str(x) for x in dim_sizes)}]'
        return f'{self.element_type}[{len_str}]'

    def __eq__(self, other, dtchain:List[str]=None):
        if not isinstance(other, ArrayType):
            return False
        # pass the dtchain along, we don't need to add anything though
        return self.num_elements == other.num_elements and \
               self.element_type.__eq__(other.element_type, dtchain)

    def __hash__(self):
        return hash((self.num_elements, self.element_type))

    def to_dict(self) -> dict:
        return {
            **self._get_base_dict(),
            'nelem': self.num_elements,
            'inner': [self.element_type.to_dict()]
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'ArrayType':
        return ArrayType(datatype_from_dict(d['inner'][0], sdb), d['nelem'])

class EnumType(DataType):
    def __init__(self, name:str, dt_size:int=4) -> None:
        super().__init__(DataTypeCategories.Enum)
        self.name = name
        self.dt_size = dt_size  # don't know if we need this, assume 4B int for now

    @property
    def size(self):
        return self.dt_size

    @property
    def type_sequence_str(self) -> str:
        return self.category

    @property
    def type_sequence(self) -> List['DataType']:
        return [self]

    @property
    def typename_basic(self) -> str:
        return self.name

    def __str__(self):
        return self.name

    def __eq__(self, other, dtchain:List[str]=None):
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

    def to_dict(self) -> dict:
        return {
            **self._get_base_dict(),
            'name': self.name,
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'EnumType':
        return EnumType(d['name'])

class FunctionType(DataType):
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

    @property
    def size(self):
        return 0    # this should have a pointer parent, whose size is meaningful

    @property
    def type_sequence_str(self) -> str:
        return self.category

    @property
    def type_sequence(self) -> List['DataType']:
        return [self]

    @property
    def typename_basic(self) -> str:
        return self.name if self.name else 'FuncProto'

    def __str__(self):
        # assumes function pointer
        return f'{self.return_dtype} (*)({",".join(str(p) for p in self.params)})'

    def __eq__(self, other, dtchain:List[str]=None):
        if not isinstance(other, FunctionType):
            return False

        if self.name != other.name:
            return False

        if not dtchain:
            dtchain = []

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

    def to_dict(self) -> dict:
        return {
            **self._get_base_dict(),
            'name': self.name,
            'rdtype': self.return_dtype.to_dict(),
            'inner': [p.to_dict() for p in self.params],
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'FunctionType':
        return FunctionType(datatype_from_dict(d['rdtype'], sdb),
                [datatype_from_dict(pdict, sdb) for pdict in d['inner']],
                d['name']
            )

_dt_from_dict_methods = {
    'ArrayType': ArrayType.from_dict,
    'BuiltinType': BuiltinType.from_dict,
    'EnumType': EnumType.from_dict,
    'FunctionType': FunctionType.from_dict,
    'PointerType': PointerType.from_dict,
    'Type': Type.from_dict,
}

def datatype_from_dict(d:dict, sdb) -> 'DataType':
    if d['kind'] not in _dt_from_dict_methods:
        raise NotImplementedError(f'DataType kind {d["kind"]} not mapped to a from_dict method')
    return _dt_from_dict_methods[d['kind']](d, sdb)

def datatype_from_json_str(json_str:str, sdb=None):
    data = json.loads(json_str)
    return datatype_from_dict(data, sdb)
