from typing import Dict, List

# throwing this together quickly, but the intent is to provide a helper class that helps
# import struct definitions from the AST, DWARF, etc. and manages some of the logic
# about unique struct definitions to prevent us from re-defining every struct type
# every single time we see it in a dataset (which is what is happening now, and we're
# hitting recursion limits as well as running unecessarily slow)

# TODO: just make this the StructDatabase -> now StructType just holds its sid and
# can wrap the internal definition of the structure layout (StructLayout) with properties
# to preserve the same API

from .datatype import datatype_from_dict, DataType

class StructField:
    '''
    Do we want to call these fields or members? would be good to be consistent...
    '''
    def __init__(self, dtype:'DataType', name:str='') -> None:
        self.dtype = dtype
        self.name = name

    @property
    def size(self):
        return self.dtype.size

    def __str__(self):
        return f'{self.dtype} {self.name}'

    def __eq__(self, other, dtchain:List[str]=None):
        if not isinstance(other, StructField):
            return False
        # NOTE: field name is not part of the comparison, just for readability
        return self.dtype.__eq__(other.dtype, dtchain)

    def __hash__(self):
        return hash((self.dtype,))

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'dtype': self.dtype.to_dict()
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'StructField':
        return StructField(datatype_from_dict(d['dtype'], sdb), d['name'])

class StructLayout:
    '''
    This defines the actual structure layout, and behaves like a simple
    record of fields and their offsets and types.
    '''
    def __init__(self, fields_by_offset:Dict[int, StructField] = None) -> None:
        self.fields_by_offset:Dict[int, StructField] = fields_by_offset if fields_by_offset else {}

    def __eq__(self, other, dtchain:List[str]=None):
        '''
        NOTE: breaking StructLayout out as its own class separate from StructDefinition
              allows us to implement equality in terms of layout content only, not the
              structure name; StructDefinition can still check names as part
              of its own equality logic.
        '''
        if not isinstance(other, StructLayout):
            return False
        if set(self.fields_by_offset.keys()) != set(other.fields_by_offset.keys()):
            return False    # set of member offsets don't match
        for off, field in self.fields_by_offset.items():
            if not field.__eq__(other.fields_by_offset[off], dtchain):
                return False
        return True

    def __hash__(self):
        # - have to sort keys to guarantee that hash is consistent
        # - use field.name instead of the field hash to avoid any recursive issues
        #   for structs that have pointers to themselves
        return hash(tuple([self.fields_by_offset[k].name for k in sorted(self.fields_by_offset.keys())]))

    def get_first_level_layout(self) -> Dict[int,str]:
        '''
        Returns a mapping of {offset: type name} for the top-level members of this
        structure (for quicker equality comparisons across translation units)
        '''
        return {off: f.dtype.typename_basic for off, f in self.fields_by_offset.items()}

    def to_dict(self) -> dict:
        return {
            off: field.to_dict() for off, field in self.fields_by_offset.items()
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

    def __eq__(self, other, dtchain:List[str]=None):
        if not isinstance(other, UnionLayout):
            return False

        if len(self.fields) != len(other.fields):
            return False

        # sadly we can't use this simple set equality version because we might
        # see recursively defined Unions (MyUnion { MyUnion* x; })
        # -------
        # if set(self.fields) != set(other.fields):
        #     return False

        # implement "set equality" here but pass the dtchain along

        remaining_fields = list(other.fields)

        for f in self.fields:
            # find a match in other
            match_idx = -1
            for i, other_field in enumerate(remaining_fields):
                if f.__eq__(other_field, dtchain):
                    match_idx = i
                    break
            if match_idx == -1:
                return False
            else:
                remaining_fields.pop(match_idx)

        return True

    def __hash__(self):
        # - use field.name instead of the field hash to avoid any recursive issues
        #   for structs that have pointers to themselves
        return hash(tuple([x.name for x in self.fields]))

    def get_first_level_layout(self) -> List[str]:
        '''
        Returns a mapping of {offset: type name} for the top-level members of this
        structure (for quicker equality comparisons across translation units)
        '''
        return [f.dtype.typename_basic for f in self.fields]

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
    def __init__(self, name:str, layout:StructLayout, is_class:bool=False) -> None:
        self.name = name
        self.layout = layout
        self.is_class = is_class

    def __eq__(self, other, dtchain:List[str]=None):
        if not isinstance(other, StructDefinition):
            return False
        if self.name != other.name:
            return False

        if not dtchain:
            dtchain = []

        dtchain_name = f'Struct_{self.name}'
        if dtchain_name in dtchain:
            return True     # we have cycled around - we are equal

        dtchain.append(dtchain_name)
        is_equal = True

        if not self.layout.__eq__(other.layout, dtchain):
            is_equal = False

        dtchain.pop()
        return is_equal

    def __hash__(self):
        return hash(self.name)      # these tend to be unique for structures...

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'layout': self.layout.to_dict(),
            'is_class': self.is_class
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'StructDefinition':
        return StructDefinition(d['name'], StructLayout.from_dict(d['layout'], sdb), d['is_class'])

class UnionDefinition:
    '''Union version of StructDefinition'''
    def __init__(self, name:str, layout:UnionLayout) -> None:
        self.name = name
        self.layout = layout

    def __eq__(self, other, dtchain:List[str]=None):
        if not isinstance(other, UnionDefinition):
            return False
        if self.name != other.name:
            return False

        if not dtchain:
            dtchain = []

        dtchain_name = f'Union_{self.name}'
        if dtchain_name in dtchain:
            return True     # we have cycled around - we are equal

        dtchain.append(dtchain_name)
        is_equal = True

        if not self.layout.__eq__(other.layout, dtchain):
            is_equal = False

        dtchain.pop()
        return is_equal

    def __hash__(self):
        return hash(self.name)

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'layout': self.layout.to_dict(),
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'UnionDefinition':
        return UnionDefinition(d['name'], UnionLayout.from_dict(d['layout'], sdb))
