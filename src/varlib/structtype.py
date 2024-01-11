from .datatype import *
from .structlayout import *
from .structdatabase import *

class StructType(DataType):
    '''
    Structure types
    '''
    def __init__(self, db:StructDatabase, sid:int=-1) -> None:
        super().__init__(DataTypeCategories.Struct)

        self.sid = sid
        self._db = db

        # TODO: I think this can go away? or at best become a property...
        # self.is_fwd_decl = False

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
