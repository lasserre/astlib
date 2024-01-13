from typing import Dict, List

from .datatype import StructField

# throwing this together quickly, but the intent is to provide a helper class that helps
# import struct definitions from the AST, DWARF, etc. and manages some of the logic
# about unique struct definitions to prevent us from re-defining every struct type
# every single time we see it in a dataset (which is what is happening now, and we're
# hitting recursion limits as well as running unecessarily slow)

# TODO: just make this the StructDatabase -> now StructType just holds its sid and
# can wrap the internal definition of the structure layout (StructLayout) with properties
# to preserve the same API

class StructLayout:
    '''
    This defines the actual structure layout, and behaves like a simple
    record of fields and their offsets and types.
    '''
    def __init__(self, fields_by_offset:Dict[int, StructField] = {}) -> None:
        self.fields_by_offset:Dict[int, StructField] = fields_by_offset

    def __eq__(self, other, dtchain:List[str]=[]):
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
    def __init__(self, name:str, layout:StructLayout) -> None:
        self.name = name
        self.layout = layout

    def __eq__(self, other, dtchain:List[str]=[]):
        if not isinstance(other, StructDefinition):
            return False
        if self.name != other.name:
            return False

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
            'layout': self.layout.to_dict()
        }

    @staticmethod
    def from_dict(d:dict, sdb) -> 'StructDefinition':
        return StructDefinition(d['name'], StructLayout.from_dict(d['layout'], sdb))
