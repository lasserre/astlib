from .datatypes import *
from .structlayout import *

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
    def fields_by_offset(self) -> Dict[int, StructField]:
        '''A dictionary mapping field offsets to their StructField definitions'''
        layout = self.layout
        return layout.fields_by_offset if layout else {}

    @property
    def size(self):
        return sum(f.size for f in self.fields_by_offset.values())

    @property
    def type_sequence(self) -> str:
        return 'STRUCT'

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
    def size(self):
        return max(f.size for f in self.fields)

    @property
    def type_sequence(self) -> str:
        return 'UNION'

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
