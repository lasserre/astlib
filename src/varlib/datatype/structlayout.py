from typing import Dict, List, Set, Union

from .datatypes import DataType

class StructField:
    '''
    Do we want to call these fields or members? would be good to be consistent...
    '''
    def __init__(self, dtype:'DataType', name:str='', comment:str=None) -> None:
        self.dtype = dtype
        self.name = name
        self.comment = comment

    @property
    def size(self):
        return self.dtype.size if self.dtype else 1     # if dtype is none, we don't know true size, but at least 1B

    def __str__(self):
        return f'{self.dtype} {self.name}'

    def __eq__(self, other):
        if not isinstance(other, StructField):
            return False
        return self.dtype == other.dtype

    def __hash__(self):
        return hash((self.dtype,))

    def __str__(self):
        comment_str = f'   // {self.comment}' if self.comment else ''
        return f'{self.dtype} {self.name}{comment_str}'

    def __repr__(self) -> str:
        return str(self)

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'dtype': self.dtype.to_dict() if self.dtype else None
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'StructField':
        return StructField(DataType.from_dict(d['dtype'], sdb), d['name'])

class StructLayout(dict):
    '''
    This defines the actual structure layout, and behaves like a simple
    record of fields and their offsets and types.

    This just wraps a dict, but is expected to have the format/type:
            Dict[int, StructField]
    '''
    def __init__(self, *arg, **kw):
        super(StructLayout, self).__init__(*arg, **kw)

    def __eq__(self, other):
        '''
        NOTE: breaking StructLayout out as its own class separate from StructDefinition
              allows us to implement equality in terms of layout content only, not the
              structure name or id; StructDefinition can still check names as part
              of its own equality logic.
        '''
        if not isinstance(other, StructLayout):
            return False
        if set(self.keys()) != set(other.keys()):
            return False    # set of member offsets don't match
        return all([field == other[off] for off, field in self.items()])

    def __hash__(self):
        # - have to sort keys to guarantee that hash is consistent
        # - use field.name instead of the field hash to avoid any recursive issues
        #   for structs that have pointers to themselves
        return hash(tuple([self[k].name for k in sorted(self.keys())]))

    def __str__(self):
        return '\n'.join([f'{k:#x}: {self[k]}' for k in sorted(self.keys())])

    def __repr__(self) -> str:
        return str(self)

    def get_first_level_layout(self) -> Dict[int,str]:
        '''
        Returns a mapping of {offset: type name} for the top-level members of this
        structure (for quicker equality comparisons across translation units)
        '''
        return {off: f.dtype.typename_basic for off, f in self.items()}

    def to_dict(self) -> dict:
        return {
            off: field.to_dict() for off, field in self.items()
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'StructLayout':
        return StructLayout({
            int(off): StructField.from_dict(field_dict, sdb) for off, field_dict in d.items()
        })

class UnionLayout:
    '''Union version of StructLayout'''
    def __init__(self, fields:List[StructField]=None):
        self.fields = fields if fields else []

    def __eq__(self, other):
        if not isinstance(other, UnionLayout):
            return False

        return set(self.fields) == set(other.fields)

    def __hash__(self):
        # - use field.name instead of the field hash to avoid any recursive issues
        #   for structs that have pointers to themselves
        return hash(tuple([x.name for x in self.fields]))

    def __str__(self):
        return '\n'.join([str(f) for f in self.fields])

    def __repr__(self) -> str:
        return str(self)

    def get_first_level_layout(self) -> Set[str]:
        '''
        Returns a mapping of {offset: type name} for the top-level members of this
        structure (for quicker equality comparisons across translation units)
        '''
        return set(f.dtype.typename_basic for f in self.fields)

    def to_dict(self) -> dict:
        return {
            'fields': [f.to_dict() for f in self.fields]
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'UnionLayout':
        return UnionLayout([
            [StructField.from_dict(fdict, sdb) for fdict in d['fields']]
        ])

class StructDefinition:
    '''
    Defines the name and content of a structure, and is logically the "database format" of a structure
    for varlib.

    This is wrapped by StructType and shouldn't be directly used other than
    in the context of the StructDatabase and to facilitate the process of reading in definitions
    where types are partially defined until we are done. Specifically this helps deal with forward
    declared types (that are empty until we know the definition later), recursively defined types
    (e.g. struct with a pointer to itself), etc.
    '''
    def __init__(self, name:str, layout:Union[StructLayout, Dict[int,StructField]], is_class:bool=False, ghidra_uid:int=-1) -> None:
        self.name = name
        self.layout = StructLayout(layout)
        self.is_class = is_class
        self.ghidra_uid = ghidra_uid

    def __eq__(self, other):
        if not isinstance(other, StructDefinition):
            return False
        return self.name == other.name and \
            self.is_class == other.is_class and \
            self.ghidra_uid == other.ghidra_uid and \
            self.layout == other.layout

    def __hash__(self):
        # names are typically unique
        return hash(self.name, self.ghidra_uid)

    def __str__(self):
        tabbed_layout = '\n'.join([f'\t{member}' for member in str(self.layout).split('\n')])
        return f'struct {self.name} {{\n{tabbed_layout}\n}}'

    def __repr__(self) -> str:
        return str(self)

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'ghidra_uid': self.ghidra_uid,
            'layout': self.layout.to_dict(),
            'is_class': self.is_class
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'StructDefinition':
        return StructDefinition(d['name'], StructLayout.from_dict(d['layout'], sdb), d['is_class'], d['ghidra_uid'])

class UnionDefinition:
    '''Union version of StructDefinition'''
    def __init__(self, name:str, layout:UnionLayout, ghidra_uid:int=-1) -> None:
        self.name = name
        self.layout = layout
        self.ghidra_uid = ghidra_uid

    def __eq__(self, other):
        if not isinstance(other, UnionDefinition):
            return False
        return self.name == other.name and \
            sefl.ghidra_uid == other.ghidra_uid and \
            self.layout == other.layout

    def __hash__(self):
        return hash(self.name, self.ghidra_uid)

    def __str__(self):
        tabbed_layout = '\n'.join([f'\t{member}' for member in str(self.layout).split('\n')])
        return f'union {self.name} {{\n{tabbed_layout}\n}}'

    def __repr__(self) -> str:
        return str(self)

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'ghidra_uid': self.ghidra_uid,
            'layout': self.layout.to_dict(),
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'UnionDefinition':
        return UnionDefinition(d['name'], UnionLayout.from_dict(d['layout'], sdb), d['ghidra_uid'])
