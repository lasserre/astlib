from itertools import chain
import json
from pathlib import Path
from typing import List, Dict, Iterable, Callable, Any, Set

from .datatype.structlayout import StructDefinition, UnionDefinition, StructLayout, UnionLayout
from .datatype.structtype import StructType, UnionType

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
        self.sid_by_tu_and_name:Dict[str, Dict[str,int]] = {}             # maps (tuid, name): sid
        self.uid_by_tu_and_name:Dict[str, Dict[str,int]] = {}             # maps (tuid, name): uid
        # (only because gdb proved you can have name collisions within a translation unit)
        self._next_sid = 0

        # this is generated on-the-fly for individual structs (see StructType.flatten())
        self.reset_flattened_structs()

    def reset_flattened_structs(self):
        self.flattened_structs:Dict[int, StructDefinition] = {}    # mirror of structs_by_id - maps SAME sids to their flattened defs

    @property
    def struct_types(self) -> Dict[int, StructType]:
        '''Dictionary mapping sid to StructType for each struct in the database'''
        return {sid: StructType(self, sid) for sid in self.structs_by_id}

    @property
    def union_types(self) -> Dict[int, UnionType]:
        '''Dictionary mapping sid to UnionType for each union in the database'''
        return {sid: UnionType(self, sid) for sid in self.unions_by_id}

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
            'sid_by_tu_and_name': self.sid_by_tu_and_name,
            'uid_by_tu_and_name': self.uid_by_tu_and_name,
            # do NOT include flattened_structs - we generate this dynamically from structs_by_id
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
        if 'uid_by_tu_and_name' in d:
            sdb.uid_by_tu_and_name = d['uid_by_tu_and_name']

        # idk that we need it, but reset this so if we add a new struct its ready to go
        max_struct_id = max(sdb.structs_by_id.keys()) + 1 if sdb.structs_by_id else 0
        max_union_id = max(sdb.unions_by_id.keys()) + 1 if sdb.unions_by_id else 0

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

    def get_sid(self, tuid:str, name:str, is_union:bool=False) -> int:
        '''
        Returns the sid for the named struct or union within this translation unit if it has
        been mapped. Returns -1 if this struct is not in the database

        ASSUMES struct and union ids are all unique from each other (no struct id will overlap a union id)
        '''
        lookup_dict = self.uid_by_tu_and_name if is_union else self.sid_by_tu_and_name
        if tuid in lookup_dict:
            if name in lookup_dict[tuid]:
                return lookup_dict[tuid][name]
        return -1   # not mapped

    def map_struct_type_empty(self, tuid:str, name:str, is_class:bool=False) -> int:
        '''
        Same as map_struct_type, but creates an empty StructureDefinition with the
        given name and returns the assigned sid
        '''
        return self.map_struct_type(tuid, StructDefinition(name, StructLayout(), is_class), is_union=False)

    def map_union_type_empty(self, tuid:str, name:str) -> int:
        return self.map_struct_type(tuid, UnionDefinition(name, UnionLayout()), is_union=True)

    def map_struct_type(self, tuid:str, sdef:Any, is_union:bool, force_sid:int=None) -> int:
        '''
        Maps stype into the given translation unit and returns the sid for the
        resulting structure.

        This should only be called if get_sid() returns -1.
        '''
        # NOTE: I don't think we can consolidate duplicate definitions across translation units
        # at this point, since map_struct_type() is called BEFORE the StructDefinition is
        # filled out (and that is by design to avoid recursion issues)

        if force_sid:
            new_sid = force_sid     # this is for maintaining existing sids
        else:
            new_sid = self._next_sid
            self._next_sid += 1

        # 1) map the sid to the definition itself
        if is_union:
            self.unions_by_id[new_sid] = sdef
        else:
            self.structs_by_id[new_sid] = sdef

        # 2) map the sid inside its translation unit (tuid/name)
        lookup_dict = self.uid_by_tu_and_name if is_union else self.sid_by_tu_and_name
        if tuid not in lookup_dict:
            lookup_dict[tuid] = {}
        lookup_dict[tuid][sdef.name] = new_sid

        # 3) add the name to our lookup by struct name
        if sdef.name not in self.sids_by_name:
            self.sids_by_name[sdef.name] = [new_sid]
        else:
            self.sids_by_name[sdef.name].append(new_sid)

        return new_sid

    def remove_struct(self, sid:int, tuid:str=''):
        if sid in self.structs_by_id:
            sname = self.structs_by_id[sid].name
            del self.sid_by_tu_and_name[tuid][sname]
            del self.structs_by_id[sid]
            if len(self.sids_by_name[sname]) > 1:
                self.sids_by_name[sname] = [x for x in self.sids_by_name[sname] if x != sid]
            else:
                del self.sids_by_name[sname]
        elif sid in self.unions_by_id:
            uname = self.unions_by_id[sid].name
            del self.uid_by_tu_and_name[tuid][uname]
            del self.unions_by_id[sid]
            if len(self.sids_by_name[uname]) > 1:
                self.sids_by_name[uname] = [x for x in self.sids_by_name[uname] if x != sid]
            else:
                del self.sids_by_name[uname]

    def update_struct_definition(self, sid:int, sdef:StructDefinition):
        '''
        Updates the structure definition in the database, invalidating any stale state
        such as the flattened version of the structure
        '''
        self.structs_by_id[sid] = sdef
        if sid in self.flattened_structs:
            del self.flattened_structs[sid]

    def build_sids_by_name(self):
        self.sids_by_name = {}

        struct_name_id_pairs = [(sdef.name, sid) for sid, sdef in self.structs_by_id.items()]
        union_name_id_pairs = [(udef.name, sid) for sid, udef in self.unions_by_id.items()]

        for name, sid in chain(struct_name_id_pairs, union_name_id_pairs):
            if name not in self.sids_by_name:
                self.sids_by_name[name] = []
            self.sids_by_name[name].append(sid)

    def find_nested_structures(self) -> List[StructType]:
        '''
        Returns a list of structures in this database which have nested structures within them
        '''
        return [stype for stype in self.struct_types.values() if stype.nested_structs]
