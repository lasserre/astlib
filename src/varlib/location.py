from typing import List

class LocationType:
    Register = 'reg'
    Stack = 'stack'
    Memory = 'mem'
    # these may be temporary...going to see how these correlate
    # with DWARF symbols first
    Join = 'JOIN'
    Unique = 'UNIQUE'
    # this is intended to represent a location that doesn't exist or is unspecified
    # (by DWARF usually), I'm adding it for variables that have no location.
    # Looking at a variable like this, I think it got optimized out. So the debug
    # info is there because it is in the source, but it doesn't exist in the binary
    # so there is no location (my guess)
    Undefined = 'UndefinedLoc'

    @staticmethod
    def get_list() -> List[str]:
        return [LocationType.Register,
                LocationType.Stack,
                LocationType.Memory,
                LocationType.Join,
                LocationType.Unique]

class Location:
    '''
    Encapsulates the location of a variable, whether it be in a register, memory,
    or relative to the stack
    '''
    def __init__(self, loc_type:str, reg_name:str='', offset:int=None) -> None:
        self.loc_type = loc_type
        self.reg_name = reg_name.lower()    # make register casing consistent
        self.offset = offset

    def __hash__(self):
        return hash((self.loc_type, self.reg_name, self.offset))

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, Location):
            if self.loc_type == LocationType.Register:
                # ignore offset for register locations
                return  self.loc_type == __value.loc_type and \
                        self.reg_name == __value.reg_name
            else:
                return  self.loc_type == __value.loc_type and \
                        self.reg_name == __value.reg_name and \
                        self.offset == __value.offset
        return False

    def __str__(self) -> str:
        if self.loc_type == LocationType.Register:
            return f'{self.reg_name}'
        elif self.loc_type == LocationType.Stack:
            return f'Stack[{self.offset:#x}]'
        elif self.loc_type == LocationType.Memory:
            if self.reg_name:
                # register-based address
                if self.offset > 0:
                    return f'Mem[{self.reg_name}+{self.offset:#x}]'
                elif self.offset < 0:
                    return f'Mem[{self.reg_name}{self.offset:#x}]'
                else:
                    return f'Mem[{self.reg_name}]'
            else:
                # memory offset
                return f'Mem[{self.offset:#x}]'
        else:
            return f'LocType={self.loc_type},Reg={self.reg_name},Off={self.offset}'

    def to_dict(self) -> dict:
        return {
            'loc_type': self.loc_type,
            'loc_off': self.offset,
            'loc_reg': self.reg_name
        }

    @staticmethod
    def from_dict(d:dict) -> 'Location':
        return Location(d['loc_type'], d['loc_reg'], int(d['loc_off']))
