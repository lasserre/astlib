from typing import List, Dict

from .structlayout import *

# Wait, I think maybe the issue is this whole recursive check altogether. If we
# adjust the algorithm, I think we can avoid it completely as well as fix our current
# problem
# TODO: when you see a new structure type, MAP IT FIRST **before** defining
# the members
# --> that way, if a member eventually leads to a recursive definition
#     that refers to itself (via pointer), it is already mapped and you just
#     return a reference to it
# --> this also means we should be dealing with one definition of the struct,
#     not making multiple copies (otherwise, not everyone gets the full definition/right version!)
# --> STRUCTS ARE UNIQUE FOR (translation unit, name) TUPLES
#     (and can be shared across translation units...just have to check against contents)

class StructDatabase:
    '''
    Holds the structure definitions across an entire program context
    '''
    def __init__(self) -> None:
        self.structs_by_id:Dict[int, StructDefinition] = {}     # maps sid: StructType
        self.sids_by_name:Dict[str, List[int]] = {}             # maps name: list of sids with this name
        self.sid_by_tu_and_name:Dict[str, Dict[str,int]] = {}   # maps (transl unit id (tuid), struct name): sid
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
    def get_sid(self, tuid:str, sname:str) -> int:
        '''
        Returns the sid for the named struct within this translation unit if it has
        been mapped. Returns -1 if this struct is not in the database
        '''
        if tuid in self.sid_by_tu_and_name:
            if sname in self.sid_by_tu_and_name[tuid]:
                return self.sid_by_tu_and_name[tuid][sname]
        return -1

    def _map_struct_by_tu_and_name(self, tuid:str, name:str, sid:int):
        if tuid not in self.sid_by_tu_and_name:
            self.sid_by_tu_and_name[tuid] = {}
        self.sid_by_tu_and_name[tuid][name] = sid

    # TODO: if we want to, just define a consolidate_duplicates()
    #
    # def consolidate_duplicates()
    #
    # - go through all the entries which share names (each list in sids_by_name.values())
    #   and group all of the identical definitions together
    #   -> IMPLEMENTATION: since I implemented __hash__ and __eq__, I think I can make a dictionary
    #      USING THE DEFINITIONS AS KEYS and test "sdef in dict"
    # - for all the sids whose definitions were identical, just map all those ids to
    #   one shared definition (pick one to keep)
    #   -> I can't get rid of the extra sids without processing whoever used it...which I can't know
    #      unless we do some kind of export where I am allowed to remap sids (idk that it matters much)

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
        self._map_struct_by_tu_and_name(tuid, sdef.name, new_sid)

        # 3) add the name to our lookup by struct name
        if sdef.name not in self.sids_by_name:
            self.sids_by_name[sdef.name] = [new_sid]
        else:
            self.sids_by_name[sdef.name].append(new_sid)

        return new_sid
