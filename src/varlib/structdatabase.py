from typing import List, Dict, Iterable, Callable

from .structlayout import *

class StructDatabase:
    '''
    Holds the structure definitions across an entire program context
    '''
    def __init__(self) -> None:
        self.structs_by_id:Dict[int, StructDefinition] = {}     # maps sid: StructType
        self.sids_by_name:Dict[str, List[int]] = {}             # maps name: list of sids with this name
        # self.sid_by_tu_and_name:Dict[str, Dict[str,int]] = {}   # maps (transl unit id (tuid), struct name): sid
        self.sid_by_tu_and_name:Dict[str, int] = {}             # maps 'tuid:name': sid
        self._next_sid = 0

    # def get_struct_type(self, tuid:str, sname:str) -> StructType:

    # NOTE: this is really where we avoid recursion and can MAP a new
    # structure type in the database even before we finish defining
    # its fields
    # (important to realize get_sid() is how this works...map_struct_type()
    #  is intended for when we do NOT have a struct mapped yet inside this
    #  translation unit - ensuring we don't already have it mapped elsewhere.
    #  But that situation won't be an issue when we are simply defining a
    #  recursive struct within a TU)


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

    # def _first_level_layouts_match(self, fll1:Dict[int,str], fll2)
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

    # def remap_structure_ids(self, walk_types:Iterable):
    #     sid_remap = self._remap_db_structure_ids()

    #     # remap each of the provided data types to match the new database ids
    #     for dt in walk_types:
    #         dt._remap_sids(sid_remap)

    # def _remap_db_structure_ids(self) -> Dict[int, int]:
    #     '''
    #     Remaps the structure ids in this database, and returns the sid_remap which
    #     maps old_sid: new_sid for all the original sids in the database.

    #     FOR THIS TO WORK PROPERLY, THE CLIENT MUST IMMEDIATELY VISIT ALL
    #     DataType objects created via this database and call dt._remap_sids() with
    #     the sid_remap returned by this function.

    #     Once that is complete, the database and all of the DataType objects referencing
    #     structs within it should be essentially rebased to a disjoint set of ids
    #     as well as consolidated such that one ID corresponds to one struct with
    #     the same name and layout (instead of one ID for name/translation unit)
    #     '''
    #     # guarantee disjoint id set (start above self._next_sid somewhere)
    #     # guarantee each sid that currently exists is in the remap
    #     remap_base_id = self._next_sid + 1000
    #     remap_base_id -= (remap_base_id % 100)
    #     next_new_id = remap_base_id

    #     new_structs_by_id = {}
    #     sid_remap = {}

    #     # split into unique sets based on actual layout/name
    #     for sname, old_sids in self.sids_by_name.items():
    #         # partition based on definition (dict keys will collect same definitions together)
    #         d:Dict[StructDefinition, List[int]] = {}  # maps sdef: list of old ids

    #         for x in old_sids:
    #             sdef = self.structs_by_id[x]
    #             if sdef not in d:
    #                 d[sdef] = [x]
    #             else:
    #                 d[sdef].append(x)

    #         for sdef in d.keys():
    #             new_structs_by_id[next_new_id] = sdef
    #             for x in d[sdef]:
    #                 sid_remap[x] = next_new_id
    #             next_new_id += 1

    #     # overwrite with new version of structs_by_id
    #     self.structs_by_id = new_structs_by_id

    #     # for consistency:
    #     # remap sids_by_name
    #     new_sids_by_name = {}
    #     for sname, old_sids in self.sids_by_name.items():
    #         new_ids = list(set([sid_remap[x] for x in old_sids]))
    #         new_sids_by_name[sname] = new_ids
    #     self.sids_by_name = new_sids_by_name

    #     # remap self.sid_by_tu_and_name?
    #     # CLS: I don't think we ever need this again...if so, I can
    #     # change this to actually remap it instead of zero it out :)
    #     self.sid_by_tu_and_name = {}

    #     return sid_remap
