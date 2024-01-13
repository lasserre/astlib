import json
from pathlib import Path
from typing import List, Dict, Iterable, Callable

from .structlayout import *

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
        self.structs_by_id:Dict[int, StructDefinition] = {}     # maps sid: StructType
        self.sids_by_name:Dict[str, List[int]] = {}             # maps name: list of sids with this name
        self.sid_by_tu_and_name:Dict[str, int] = {}             # maps 'tuid:name': sid
        self._next_sid = 0

    def to_dict(self) -> Dict[int, dict]:
        '''
        Converts the database into a dictionary-based format ready for JSON serialization
        '''
        # we only need to save off structs_by_id
        # - rebuild sids_by_name as we read it in (don't save here)
        # - sid_by_tu_and_name is only for initial construction, at this point we are done
        #   and you only look up structs via sid
        return {sid: sdef.to_dict() for sid, sdef in self.structs_by_id.items()}

    @staticmethod
    def from_dict(d:Dict[int,dict]) -> 'StructDatabase':
        sdb = StructDatabase()
        sdb.structs_by_id = {int(sid): StructDefinition.from_dict(sd_dict, sdb) for sid, sd_dict in d.items()}

        print(f'CLS: I think sids will be strings here...confirm, then convert to int first', flush=True)
        # rebuild sids_by_name
        for sid, sdef in sdb.structs_by_id.items():
            if sdef.name not in sdb.sids_by_name:
                sdb.sids_by_name[sdef.name] = [sid]
            else:
                sdb.sids_by_name[sdef.name].append(sid)

        # idk that we need it, but reset this so if we add a new struct its ready to go
        sdb._next_sid = max(sdb.structs_by_id.keys()) + 1
        return sdb

    def to_json(self, filepath:Path):
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @staticmethod
    def from_json(filepath:Path) -> 'StructDatabase':
        with open(filepath, 'r') as f:
            data = json.load(f)
        return StructDatabase.from_dict(data)

    def _get_struct_key(self, tuid:str, sname:str) -> str:
        return f'{tuid}:{sname}'

    def get_sid(self, tuid:str, sname:str, is_fwd_decl:bool, get_first_level_layout:Callable[[], Dict[int,str]]) -> int:
        '''
        Returns the sid for the named struct within this translation unit if it has
        been mapped. Returns -1 if this struct is not in the database
        '''
        struct_key = self._get_struct_key(tuid, sname)

        # simple lookup via tuid/name first to see if already mapped
        if struct_key in self.sid_by_tu_and_name:
            return self.sid_by_tu_and_name[struct_key]

        if is_fwd_decl:
            # NOTE: fwd decls have to be separate from below because we're ok matching
            # no definition of a fwd decl with an existing definition
            if sname in self.sids_by_name:
                # match fwd decl to first mapped struct by this name
                sid_match = self.sids_by_name[sname][0]
                self.sid_by_tu_and_name[struct_key] = sid_match     # save mapping for consistency/next time
                return sid_match
            return -1   # need to define a new type, setting .is_fwd_decl = True

        # check for a match based on get_first_level_layout
        if sname in self.sids_by_name:
            new_layout = get_first_level_layout()
            for sid in self.sids_by_name[sname]:
                fllayout = self.structs_by_id[sid].layout.get_first_level_layout()
                if not fllayout or fllayout == new_layout:
                    # match an empty layout (existing fwd decl) or an actual match
                    self.sid_by_tu_and_name[struct_key] = sid   # map it in this tu for next time
                    return sid

        return -1   # unable to find a match anywhere

    def map_struct_type_empty(self, tuid:str, name:str) -> int:
        '''
        Same as map_struct_type, but creates an empty StructureDefinition with the
        given name and returns the assigned sid
        '''
        return self.map_struct_type(tuid, StructDefinition(name, StructLayout()))

    def map_struct_type(self, tuid:str, sdef:StructDefinition) -> int:
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
        self.structs_by_id[new_sid] = sdef

        # 2) map the sid inside its translation unit (tuid/name)
        struct_key = self._get_struct_key(tuid, sdef.name)
        self.sid_by_tu_and_name[struct_key] = new_sid

        # 3) add the name to our lookup by struct name
        if sdef.name not in self.sids_by_name:
            self.sids_by_name[sdef.name] = [new_sid]
        else:
            self.sids_by_name[sdef.name].append(new_sid)

        return new_sid
