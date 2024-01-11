from .datatype import *
from .structlayout import *
from .structdatabase import *

class StructType(DataType):
    '''
    Structure types
    '''
    def __init__(self, db:StructDatabase, sid:int=-1, parent:DataType=None) -> None:
        super().__init__(DataTypeCategories.Struct, parent)

        self.sid = sid
        self._db = db

        # TODO: I think this can go away? or at best become a property...
        # self.is_fwd_decl = False

    @property
    def name(self):
        if self.sid < 0:
            return ''
        return self._db.structs_by_id[self.sid].name

    @property
    def fields_by_offset(self) -> Dict[int, StructField]:
        if self.sid < 0:
            return {}
        return self._db.structs_by_id[self.sid].layout.fields_by_offset

    @property
    def size(self):
        return sum(f.size for f in self.fields_by_offset.values())

    @property
    def type_sequence(self) -> str:
        return 'STRUCT'

    @property
    def _struct_def(self) -> StructDefinition:
        if self.sid < 0:
            return None
        return self._db.structs_by_id[self.sid]

    def __str__(self):
        return self.name

    def __eq__(self, other):
        if not isinstance(other, StructType):
            return False
        return self._struct_def == other._struct_def

    def __hash__(self):
        return hash(self.name)      # you know, these are generally unique! lol
