from .datatypes import *
from .structlayout import *
from typing import Iterable, Tuple

class StructTypeBasic(DataType):
    '''
    Fake StructType whose only role is to participate in typename_basic
    '''
    def __init__(self, name:str):
        super().__init__(DataTypeCategories.Struct)
        self.name = name

    @property
    def typename_basic(self) -> str:
        return self.name

class StructType(DataType):
    '''
    Structure types
    '''
    def __init__(self, db:'StructDatabase', sid:int=-1, is_class:bool=False, name:str='') -> None:
        super().__init__(DataTypeCategories.Struct)

        self.sid = sid
        self._db = db
        self._local_name = name     # a name we can show for cases where we don't have the StructDatabase

    @property
    def empty(self) -> bool:
        '''
        True if this structure has no content defined
        (e.g. is a forward declaration)
        '''
        return not bool(self.fields_by_offset)

    @property
    def name(self):
        '''The name of the structure'''
        if self._db is None:
            return self._local_name
        return '' if self.sid < 0 else self._db.structs_by_id[self.sid].name

    @property
    def layout(self) -> StructLayout:
        '''The member layout information for the structure'''
        return None if self.sid < 0 else self._db.structs_by_id[self.sid].layout

    @property
    def is_class(self) -> bool:
        '''True if this is a class type (C++) and not a simple struct'''
        return self._struct_def.is_class if self._struct_def else False

    @layout.setter
    def layout(self, value:StructLayout):
        if self.sid < 0:
            return
        self._db.structs_by_id[self.sid].layout = value

    @property
    def ghidra_uid(self) -> int:
        if self.sid >= 0 and self._db:
            return self._db.structs_by_id[self.sid].ghidra_uid
        return -1

    @property
    def fields_by_offset(self) -> Dict[int, StructField]:
        '''A dictionary mapping field offsets to their StructField definitions'''
        layout = self.layout
        return layout.fields_by_offset if layout else {}

    @property
    def size(self):
        return sum(f.size for f in self.fields_by_offset.values())

    @property
    def type_sequence_str(self) -> str:
        return self.category

    @property
    def type_sequence(self) -> List['DataType']:
        return [self]

    @property
    def typename_basic(self) -> str:
        return self.name

    @property
    def _struct_def(self) -> StructDefinition:
        if self.sid < 0:
            return None
        return self._db.structs_by_id[self.sid]

    def __str__(self):
        return self.name

    def __repr__(self) -> str:
        return str(self._struct_def) if self._db else f'struct {self} (sid={self.sid})'

    def __eq__(self, other, dtchain:List[str]=None):
        if not isinstance(other, StructType):
            return False
        if self._struct_def is None:
            return other._struct_def is None    # technically equal :)
        return self._struct_def.__eq__(other._struct_def, dtchain)

    def __hash__(self):
        return hash(self.name)      # you know, these are generally unique! lol

    def to_dict(self) -> dict:
        return {
            **self._get_base_dict(),
            'sid': self.sid,
            'name': self.name,
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'StructType':
        return StructType(sdb, d['sid'], name=d['name'])

    def flatten(self:'StructType', flatten_arrays:bool=False) -> 'StructType':
        '''
        Flatten this structure definition and return as a new StructType
        '''
        db:'StructDatabase' = self._db

        # to use StructType instances (which greatly simplifies any nested
        # structures to be flattened), we have to map the flat versions in
        # the database. These will be mapped as usual in the database and
        # a mapping from original sid -> flat sid is also added on to the
        # database (flattened_structs) to maintain a 1-1 mapping from any
        # sid to its flat version

        if not hasattr(db, 'flattened_structs'):
            db.flattened_structs = {}   # maps original (non-flat) sid: flattened sid

        if self.name.endswith(':FLAT'):
            return self    # this is a flattened layout

        if self.sid in db.flattened_structs:
            return StructType(db, sid=db.flattened_structs[self.sid])

        flat_name = f'{self.name}:FLAT'
        flat_layout = {}

        for off, field in self.layout.items():
            field:StructField
            for flat_off, flat_field in iter_flattened_components(field, flatten_arrays):
                flat_layout[off + flat_off] = flat_field

        sdef = StructDefinition(flat_name, StructLayout(flat_layout))
        flat_sid = db.map_struct_type('flat', sdef, is_union=False)
        db.flattened_structs[flat_sid] = self.sid

        return StructType(db, flat_sid)


# NOTE: I think unions should be treated as their own type...
# since we care so much about offsets in structure recovery,
# unions are handled quite differently since everything is at
# offset = 0.

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
    def __init__(self, db:'StructDatabase', sid:int=-1, name:str='') -> None:
        super().__init__(DataTypeCategories.Union)
        self.sid = sid
        self._db = db
        self._local_name = name     # a name we can show for cases where we don't have the StructDatabase

    @property
    def name(self):
        '''The name of the union'''
        if self._db is None:
            return self._local_name
        return '' if self.sid < 0 else self._db.unions_by_id[self.sid].name

    @property
    def empty(self) -> bool:
        '''
        True if this union has no content defined
        (e.g. is a forward declaration)
        '''
        return not bool(self.fields)

    @property
    def fields(self) -> List[StructField]:
        '''A list of the fields in the union'''
        layout = self.layout
        return layout.fields if layout else []

    @property
    def layout(self) -> UnionLayout:
        '''The member layout information for the structure'''
        return None if self.sid < 0 else self._db.unions_by_id[self.sid].layout

    @layout.setter
    def layout(self, value:UnionLayout):
        if self.sid < 0:
            return
        self._db.unions_by_id[self.sid].layout = value

    @property
    def ghidra_uid(self) -> int:
        if self.sid >= 0 and self._db:
            return self._db.unions_by_id[self.sid].ghidra_uid
        return -1

    @property
    def size(self):
        return max(f.size for f in self.fields)

    @property
    def type_sequence_str(self) -> str:
        return self.category

    @property
    def type_sequence(self) -> List['DataType']:
        return [self]

    @property
    def typename_basic(self) -> str:
        return self.name

    @property
    def _union_def(self) -> UnionDefinition:
        if self.sid < 0:
            return None
        return self._db.unions_by_id[self.sid]

    def __str__(self):
        return self.name

    def __repr__(self) -> str:
        return str(self._union_def) if self._db else f'union {self} (sid={self.sid})'

    def __hash__(self):
        return hash(tuple(self.fields))

    def __eq__(self, other, dtchain:List[str]=None):
        if not isinstance(other, UnionType):
            return False
        if self._union_def is None:
            return other._union_def is None    # technically equal :)
        return self._union_def.__eq__(other._union_def, dtchain)

    def to_dict(self) -> dict:
        return {
            **self._get_base_dict(),
            'sid': self.sid,
            'name': self.name,
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'UnionType':
        return UnionType(sdb, d['sid'], d['name'])

from .datatypes import _dt_from_dict_methods
_dt_from_dict_methods['StructType'] = StructType.from_dict
_dt_from_dict_methods['UnionType'] = UnionType.from_dict


def iter_flattened_components(field:StructField, flatten_arrays) -> Iterable[Tuple[int, StructField]]:
    '''
    Flattens the data type, returning an iterable of flattened atomic fields
    and their offsets relative to dtype. Composite types will be broken down into atomic
    elements, while basic types will remain unchanged

    Returns an iterable of (offset, type, name)
    '''
    if isinstance(field.dtype, StructType):
        for off, nested_field in field.dtype.layout.items():
            for flat_off, flat_field in iter_flattened_components(nested_field, flatten_arrays):
                yield (off + flat_off, StructField(flat_field.dtype, f'{field.name}:{flat_field.name}'))
    elif isinstance(field.dtype, ArrayType) and flatten_arrays:
        for i in range(field.dtype.num_elements):
            arr_element_field = StructField(field.dtype.element_type, f'{field.name}:{i}')
            for flat_off, flat_field in iter_flattened_components(arr_element_field, flatten_arrays):
                yield (i*field.dtype.element_type.size + flat_off, flat_field)
    else:
        yield (0, field)
