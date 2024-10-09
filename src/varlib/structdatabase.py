from itertools import chain
import json
from pathlib import Path
from typing import List, Dict, Iterable, Callable, Any, Set

from .datatype.structlayout import StructDefinition, UnionDefinition, StructLayout, UnionLayout

# NOTE: we avoid recursion by MAPPING a new structure type in the database
# even before we finish defining its fields

# UPDATED DESIGN
# 1. when you map an sid, it is permanent
#   - thus, if you map a new struct that matches an existing one,
#     we will return you the existing sid so you always line up
#   - thus, no remapping should be required
# 2. fwd decls match the first struct with same name
#   - this should work fine with #1
# 3. to compare if 2 structs are the same
#   a) set of offsets are the same
#   b) first level type names are the same, where the type
#      names are as they would be in source code, but we
#      DO NOT BUILD A FULL DEFINITION FOR THIS
#       - e.g. int, float*, MyStruct, eType, int[5], FuncProto*

class StructDatabase:
    '''
    Holds the structure definitions across an entire program context
    '''
    def __init__(self) -> None:
        self.structs_by_id:Dict[int, StructDefinition] = {}     # maps sid: StructDefinition
        self.unions_by_id:Dict[int, UnionDefinition] = {}       # maps sid: UnionDefinition
        self.sids_by_name:Dict[str, List[int]] = {}             # maps name: list of sids with this name
        self.sid_by_tu_and_name:Dict[tuple, int] = {}             # maps (tuid, name): sid
        self._next_sid = 0

    def to_dict(self) -> Dict[int, dict]:
        '''
        Converts the database into a dictionary-based format ready for JSON serialization
        '''
        return {
            'structs_by_id': {
                sid: sdef.to_dict() for sid, sdef in self.structs_by_id.items()
            },
            'unions_by_id': {
                sid: udef.to_dict() for sid, udef in self.unions_by_id.items()
            },
            'sids_by_name': self.sids_by_name,
            'sid_by_tu_and_name': self.sid_by_tu_and_name
        }

    @staticmethod
    def from_dict(d:Dict[int,dict]) -> 'StructDatabase':
        sdb = StructDatabase()
        sdb.structs_by_id = {int(sid): StructDefinition.from_dict(sd_dict, sdb) for sid, sd_dict in d['structs_by_id'].items()}
        sdb.unions_by_id = {int(sid): UnionDefinition.from_dict(ud_dict, sdb) for sid, ud_dict in d['unions_by_id'].items()}

        if 'sids_by_name' in d:
            sdb.sids_by_name = d['sids_by_name']
        else:
            # rebuild sids_by_name (backwards compatible)
            for sid, sdef in chain(sdb.structs_by_id.items(), sdb.unions_by_id.items()):
                if sdef.name not in sdb.sids_by_name:
                    sdb.sids_by_name[sdef.name] = [sid]
                else:
                    sdb.sids_by_name[sdef.name].append(sid)

        if 'sid_by_tu_and_name' in d:
            sdb.sid_by_tu_and_name = d['sid_by_tu_and_name']

        # idk that we need it, but reset this so if we add a new struct its ready to go
        max_struct_id = max(sdb.structs_by_id.keys()) + 1
        max_union_id = max(sdb.unions_by_id.keys()) + 1

        sdb._next_sid = max(max_struct_id, max_union_id)
        return sdb

    def to_json(self, filepath:Path):
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @staticmethod
    def from_json(filepath:Path) -> 'StructDatabase':
        with open(filepath, 'r') as f:
            data = json.load(f)
        return StructDatabase.from_dict(data)

    def _matches_existing_union_fllayout(self, existing_sid:int, new_ulayout:Set[str]) -> bool:
        ulayout = self.unions_by_id[existing_sid].layout.get_first_level_layout()
        # match an empty layout (existing fwd decl) or an actual match
        return (not ulayout) or ulayout == new_ulayout

    def _matches_existing_struct_fllayout(self, existing_sid:int, new_slayout:Dict[int, str]) -> bool:
        fllayout = self.structs_by_id[existing_sid].layout.get_first_level_layout()
        # match an empty layout (existing fwd decl) or an actual match
        return (not fllayout) or fllayout == new_slayout

    def _is_struct_id(self, sid:int) -> bool:
        return sid in self.structs_by_id

    def _is_union_id(self, uid:int) -> bool:
        return uid in self.unions_by_id

    def get_sid(self, tuid:str, name:str) -> int:
        '''
        Returns the sid for the named struct or union within this translation unit if it has
        been mapped. Returns -1 if this struct is not in the database

        ASSUMES struct and union ids are all unique from each other (no struct id will overlap a union id)
        '''
        if (tuid, name) in self.sid_by_tu_and_name:
            return self.sid_by_tu_and_name[(tuid, name)]
        return -1   # not mapped

    def map_struct_type_empty(self, tuid:str, name:str, is_class:bool=False) -> int:
        '''
        Same as map_struct_type, but creates an empty StructureDefinition with the
        given name and returns the assigned sid
        '''
        return self.map_struct_type(tuid, StructDefinition(name, StructLayout(), is_class), is_union=False)

    def map_union_type_empty(self, tuid:str, name:str) -> int:
        return self.map_struct_type(tuid, UnionDefinition(name, UnionLayout()), is_union=True)

    def map_struct_type(self, tuid:str, sdef:Any, is_union:bool) -> int:
        '''
        Maps stype into the given translation unit and returns the sid for the
        resulting structure.

        This should only be called if get_sid() returns -1.
        '''
        # NOTE: I don't think we can consolidate duplicate definitions across translation units
        # at this point, since map_struct_type() is called BEFORE the StructDefinition is
        # filled out (and that is by design to avoid recursion issues)

        # assume this is a new type...either brand new name or a unique def for an existing name
        # --> map as new type
        new_sid = self._next_sid
        self._next_sid += 1

        # 1) map the sid to the definition itself
        if is_union:
            self.unions_by_id[new_sid] = sdef
        else:
            self.structs_by_id[new_sid] = sdef

        # 2) map the sid inside its translation unit (tuid/name)
        self.sid_by_tu_and_name[(tuid, sdef.name)] = new_sid

        # 3) add the name to our lookup by struct name
        if sdef.name not in self.sids_by_name:
            self.sids_by_name[sdef.name] = [new_sid]
        else:
            self.sids_by_name[sdef.name].append(new_sid)

        return new_sid
