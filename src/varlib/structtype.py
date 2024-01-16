from .datatype import *
from .structlayout import *
from .structdatabase import *

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
    def __init__(self, db:StructDatabase, sid:int=-1, is_class:bool=False) -> None:
        super().__init__(DataTypeCategories.Struct)

        self.sid = sid
        self._db = db

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

    def __eq__(self, other, dtchain:List[str]=[]):
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
            'sid': self.sid
        }

    @staticmethod
    def from_dict(d:dict, sdb:StructDatabase) -> 'StructType':
        return StructType(sdb, d['sid'])

from .datatype import _dt_from_dict_methods
_dt_from_dict_methods['StructType'] = StructType.from_dict
