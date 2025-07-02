from itertools import chain
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

_dt_from_dict_methods = {}  # this is filled in below

class DataType:
    '''
    Abstract base DataType class
    '''
    def __init__(self, category:str) -> None:
        self._category = category   # readonly

    @staticmethod
    def from_dict(d:dict, sdb) -> 'DataType':
        if d is None:
            return None     # support dirty types being stored in RetypedVariablesDatabase
        if d['kind'] not in _dt_from_dict_methods:
            raise NotImplementedError(f'DataType kind {d["kind"]} not mapped to a from_dict method')
        return _dt_from_dict_methods[d['kind']](d, sdb)

    @staticmethod
    def from_json(json_str:str, sdb=None) -> 'DataType':
        data = json.loads(json_str)
        return DataType.from_dict(data, sdb)

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

    def ptr_hierarchy(self, N:int=3) -> List[str]:
        '''
        Returns the N-element (fixed-length) pointer hierarchy for this data type
        as a list of strings, where each element in the list is 'A' (array),
        'P' (pointer), or 'L' (leaf)

        The hierarchy size (N) represents the maximum number of pointers that
        can be expressed; this also is equivalent to a type sequence length of N+1
        (N pointer hierarchy elements + 1 leaf type)
        '''
        # grab all but the final (leaf) type and take only the first character of each
        ptr_list = [x[0] for x in self.type_sequence_str.split(',')[:-1]]
        # pad to fixed length
        ptr_list += ['L'] * (N-len(ptr_list))
        return ptr_list[:N]     # chop off at the first N elements

    @property
    def leaf_type(self) -> 'DataType':
        return self.type_sequence[-1]

    @property
    def primitive_size(self) -> int:
        '''
        The data type size that should be predicted by the primitive type
        recovery model. Specifically return sizes of 0 for all non-primitive types
        (structs, unions, etc) since we are not predicting a size for non-primitive
        types in this model
        '''
        return 0    # default to 0

    @property
    def is_floating(self) -> bool:
        return False    # default to false

    @property
    def is_signed(self) -> bool:
        return False    # default to false

    @property
    def is_bool(self) -> bool:
        return False    # default to false

    def to_dict(self) -> dict:
        '''Converts the data type into a serializable dict'''
        raise NotImplementedError(f'to_dict not implemented in {self.__class__.__name__}')

    def to_json(self) -> str:
        '''Serializes this type as a json string'''
        return json.dumps(self.to_dict())

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

_builtin_floats_by_size = {
    4: 'float',
    8: 'double',
    10: 'long double',
    # 16: '',
}

_builtin_uints_by_size = {
    1: 'uchar',
    2: 'ushort',
    4: 'uint32',
    8: 'uint64',
    16: 'uint128',
    # NOTE: these are simply because Ghidra generates them for "functions"
    # like ZEXT, etc. and for that reason they can show up as temporary var
    # types (as well as data types for AST nodes in expressions)
    32: 'uint256',
    64: 'uint512',
}

_builtin_ints_by_size = {
    1: 'char',
    2: 'short',
    4: 'int32',
    8: 'int64',
    16: 'int128',
}

_builtin_floats_by_name = {nm: sz for sz, nm in _builtin_floats_by_size.items()}
_builtin_uints_by_name = {nm: sz for sz, nm in _builtin_uints_by_size.items()}
_builtin_ints_by_name = {nm: sz for sz, nm in _builtin_ints_by_size.items()}

_builtin_type_names = list(chain(
    _builtin_floats_by_name.keys(),
    _builtin_uints_by_name.keys(),
    _builtin_ints_by_name.keys(),
    ['void', 'bool']
))

class BuiltinType(DataType):
    '''
    Built-in/primitive types like int, float, long, etc.

    void is also considered a built-in type with a size of 0
    bool is also considered a built-in type with a size of 1
    '''
    def __init__(self, name:str,
                 floating_point:bool, signed:bool, size:int, boolean:bool=False) -> None:
        super().__init__(DataTypeCategories.BuiltIn)
        self._name = name
        self._floating_point = floating_point
        self._signed = signed
        self._boolean = boolean
        self._size = size

    @property
    def name(self) -> str:
        return self._name

    @property
    def primitive_size(self) -> int:
        # valid sizes are: 0, 1, 2, 4, 8, 16
        # (long doubles are encoded with a "size" of 16)
        # --> round up to next valid size

        # check for valid sizes first since this should be vast majority
        if self._size in [0, 1, 2, 4, 8, 16]:
            return self._size
        elif self._size == 3:
            return 4
        elif self._size > 4 and self._size < 8:
            return 8
        else:
            return 16

    @property
    def is_floating(self) -> bool:
        return self._floating_point

    @property
    def is_signed(self) -> bool:
        return self._signed

    @property
    def is_bool(self) -> bool:
        return self._boolean

    @staticmethod
    def get_std_names() -> List[str]:
        '''Returns a list of the recognized built-in type names'''
        global _builtin_type_names
        return _builtin_type_names.copy()

    @staticmethod
    def from_standard_name(std_name:str) -> 'BuiltinType':
        global _builtin_floats_by_name, _builtin_uints_by_name, _builtin_ints_by_name

        if std_name in _builtin_floats_by_name:
            size = _builtin_floats_by_name[std_name]
            return BuiltinType(std_name, floating_point=True, signed=True, size=size)
        elif std_name in _builtin_ints_by_name:
            size = _builtin_ints_by_name[std_name]
            return BuiltinType(std_name, floating_point=False, signed=True, size=size)
        elif std_name in _builtin_uints_by_name:
            size = _builtin_uints_by_name[std_name]
            return BuiltinType(std_name, floating_point=False, signed=False, size=size)
        elif std_name == 'void':
            return BuiltinType.create_void_type()
        elif std_name == 'bool':
            return BuiltinType.create_bool_type()

        raise Exception(f'{std_name} is not a standard built-in type name')

    @property
    def standard_name(self) -> str:
        '''
        Returns a consistent name for a primitive type given its core
        properties (sign, size, isFloating), as opposed to the identifier given
        to the type by the data source (e.g. uint vs. unsigned int)

        This facilitates equality comparison using only the string name
        '''
        if self.is_bool:
            return 'bool'
        if self.is_void:
            return 'void'
        if self.is_floating:
            if self.size in _builtin_floats_by_size:
                return _builtin_floats_by_size[self.size]
            elif self.size == 16:
                # don't map 16 -> long double in _builtin_floats_by_size to keep the size/name lookup 1-1,
                # but allow for 16B/10B floats to both be treated as long doubles here
                return 'long double'
            return f'UNMAPPED_FLOAT_{self.size}'
        if self.is_signed:
            if self.size not in _builtin_ints_by_size:
                # same as below...
                if self.size < 4:
                    return _builtin_ints_by_size[4]
                elif self.size < 8:
                    return _builtin_ints_by_size[8]
                elif self.size < 16:
                    return _builtin_ints_by_size[16]
                else:
                    return f'UNMAPPED_INT_{self.size}'
            return _builtin_ints_by_size[self.size]
        else:
            if self.size not in _builtin_uints_by_size:
                # round these sizes up to next largest type - Ghidra has undefined3/5/6/7 types that aren't in our
                # type system (and rarely occur...so far I've only seen this for an invalid function or non-DWARF vars)
                if self.size < 4:
                    return _builtin_uints_by_size[4]
                elif self.size < 8:
                    return _builtin_uints_by_size[8]
                elif self.size < 16:
                    return _builtin_uints_by_size[16]
                else:
                    return f'UNMAPPED_UINT_{self.size}'
            return _builtin_uints_by_size[self.size]

    @property
    def typename_basic(self) -> str:
        return self.standard_name

    def __str__(self):
        return self.standard_name

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other):
        if not isinstance(other, BuiltinType):
            return False
        return self.is_floating == other.is_floating and \
            self.is_signed == other.is_signed and \
            self.size == other.size and \
            self.is_bool == other.is_bool

    def __hash__(self):
        return hash((self.is_floating, self.is_signed, self.size, self.is_bool))

    @staticmethod
    def create_void_type():
        '''Create a new BuiltinType instance that represents the void type'''
        return BuiltinType('void', floating_point=False, signed=False, size=0)

    @staticmethod
    def create_bool_type():
        '''
        Create a new BuiltinType instance that represents the bool type.

        We represent all bool types with this representative 1-byte bool type,
        whether or not it is actually 1 byte in the binary
        '''
        return BuiltinType('bool', floating_point=False, signed=False, size=1, boolean=True)

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
            'is_fp': self.is_floating,
            'signed': self.is_signed,
            'size': self.size,
            'boolean': self.is_bool
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'BuiltinType':
        name = d['name']

        # NOTE: tolerate missing 'boolean' key since decompiler does NOT write this
        # -> if Ghidra decompiler named it 'bool' we treat it as our (single) 1B bool type
        is_bool = d['boolean'] if 'boolean' in d else (name == 'bool')

        return BuiltinType(name=d['name'], floating_point=d['is_fp'], signed=d['signed'], size=d['size'], boolean=is_bool)

class PointerType(DataType):
    '''
    Pointer types
    '''
    def __init__(self, pointed_to:DataType, pointer_size:int) -> None:
        super().__init__(DataTypeCategories.Pointer)
        self._pointed_to = pointed_to
        self._pointer_size = pointer_size

    @property
    def pointed_to(self) -> DataType:
        return self._pointed_to

    @property
    def pointer_size(self) -> int:
        return self._pointer_size

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

    @property
    def is_funcptr_chain(self) -> bool:
        '''True if this is a chain of 1 or more pointers to a function prototype'''
        next_type = self.pointed_to
        while next_type and isinstance(next_type, PointerType):
            next_type = next_type.pointed_to

        # reached the first non-ptr type. this is a funcptr chain if this type
        # is a FunctionType
        return bool(next_type and isinstance(next_type, FunctionType))

    def __str__(self):
        if self.pointed_to:
            if self.is_funcptr_chain:
                proto_str = str(self.pointed_to)
                idx = proto_str.find('(')   # find first open paren, insert our pointer char in the chain
                prefix = proto_str[:idx+1]
                suffix = proto_str[idx+1:]
                return f'{prefix}*{suffix}'
            return f'{self.pointed_to}*'
        return '*'

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other):
        if not isinstance(other, PointerType):
            return False
        return self.pointed_to.__eq__(other.pointed_to)

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
        return PointerType(DataType.from_dict(d['inner'][0], sdb), d['size'])

class ArrayType(DataType):
    '''
    Array types
    '''
    def __init__(self, element_type:DataType, num_elements:int) -> None:
        super().__init__(DataTypeCategories.Array)
        self._element_type = element_type
        self._num_elements = num_elements

    @property
    def num_elements(self) -> int:
        return self._num_elements

    @property
    def element_type(self) -> DataType:
        return self._element_type

    @property
    def inner(self):
        return [self.element_type]

    @property
    def size(self):
        num_elements = self.num_elements if self.num_elements else 1    # assume at least 1 element (if we have no num_elements specified yet)
        return num_elements * self.element_type.size

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

    def _get_nelem_str(self, num_elements:int) -> str:
        return str(num_elements) if num_elements else ''

    def __str__(self):
        if isinstance(self.element_type, ArrayType):
            # {self.element_type}[self_dim][child_dim][...]
            nested = self.element_type
            dim_sizes = [self._get_nelem_str(self.num_elements)]     # we want top->bottom going L->R
            while isinstance(nested, ArrayType):
                dim_sizes.append(self._get_nelem_str(nested.num_elements))
                nested = nested.element_type
            eltype_str = str(nested) if nested else ''
            return f'{eltype_str}[{"][".join(str(x) for x in dim_sizes)}]'
        eltype_str = str(self.element_type) if self.element_type else ''
        return f'{eltype_str}[{self._get_nelem_str(self.num_elements)}]'

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other):
        if not isinstance(other, ArrayType):
            return False
        return self.num_elements == other.num_elements and \
               self.element_type == other.element_type

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
        return ArrayType(DataType.from_dict(d['inner'][0], sdb), d['nelem'])

class EnumType(DataType):
    def __init__(self, name:str, dt_size:int=4) -> None:
        super().__init__(DataTypeCategories.Enum)
        self._name = name
        self._dt_size = dt_size  # don't know if we need this, assume 4B int for now

    @property
    def name(self) -> str:
        return self._name

    @property
    def size(self):
        return self._dt_size

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

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other):
        if not isinstance(other, EnumType):
            return False

        # SIMPLE NAME COMPARISON for equality since I don't think we
        # will care about recovering enum "sets"/definitions per se
        # (it's likely we "mask" enums out as ints or something...)
        # -> if we need to differentiate, then come back and FIXME
        return self.name == other.name

    def __hash__(self):
        return hash((self.name, self.size))

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
        self._return_dtype = return_dtype
        self._params = params
        self._name = name

    @property
    def return_dtype(self) -> DataType:
        return self._return_dtype

    @property
    def params(self) -> List[DataType]:
        return self._params

    @property
    def name(self) -> str:
        return self._name

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
        # assumes function pointer, but PointerType parent will add the appropriate # of '*' characters
        return self.code_string()

    def __repr__(self) -> str:
        return str(self)

    def code_string(self, varname:str=None, pointer_levels:int=0) -> str:
        name = varname if varname is not None else self.name
        ptr_str = '*'*pointer_levels
        return_type_str = '' if self.return_dtype is None else f'{self.return_dtype} '
        return f'{return_type_str}({ptr_str}{name})({",".join(str(p) for p in self.params)})'

    @staticmethod
    def func_dtypes_equal(dt1:DataType, dt2:DataType):
        # only an issue if dt1 and dt2 are BOTH FunctionTypes, so we can just check dt1
        if 'FUNC' in dt1.type_sequence_str:
            # compare simple types only to avoid recursing into FunctionType.__eq__
            return dt1.type_sequence_str == dt2.type_sequence_str
        return dt1 == dt2       # normal comparison

    def __eq__(self, other):
        if not isinstance(other, FunctionType):
            return False

        if self.name != other.name:
            return False

        # compare param/return types using simple type sequences only
        # if needed to avoid recursing into FunctionType __eq__() - we don't handle cycles right now
        # --> thus, we cannot currently differentiate between function pointers which
        #     accept or return OTHER function pointers of different prototypes
        #     (not an issue for what I need right now, but later we may want this)
        if not FunctionType.func_dtypes_equal(self.return_dtype, other.return_dtype):
            return False

        if len(self.params) != len(other.params):
            return False

        for i, p in enumerate(self.params):
            if not FunctionType.func_dtypes_equal(p, other.params[i]):
                return False

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
        return FunctionType(DataType.from_dict(d['rdtype'], sdb),
                [DataType.from_dict(pdict, sdb) for pdict in d['inner']],
                d['name']
            )

# fill this in now that these types are defined
_dt_from_dict_methods['ArrayType'] = ArrayType.from_dict
_dt_from_dict_methods['BuiltinType'] = BuiltinType.from_dict
_dt_from_dict_methods['EnumType'] = EnumType.from_dict
_dt_from_dict_methods['FunctionType'] = FunctionType.from_dict
_dt_from_dict_methods['PointerType'] = PointerType.from_dict
_dt_from_dict_methods['Type'] = Type.from_dict
