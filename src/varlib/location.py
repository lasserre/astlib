from typing import List

class LocationType:
    Register = 'reg'
    Stack = 'stack'
    Memory = 'mem'

    @staticmethod
    def get_list() -> List[str]:
        return [LocationType.Register,
                LocationType.Stack,
                LocationType.Memory]

class Location:
    '''
    Encapsulates the location of a variable, whether it be in a register, memory,
    or relative to the stack
    '''
    def __init__(self, loc_type:str, reg_name:str='', offset:int=None) -> None:
        self.loc_type = loc_type
        self.reg_name = reg_name.lower()    # make register casing consistent
        self.offset = offset

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, Location):
            if self.loc_type == LocationType.Register:
                # ignore offset for register locations
                return  self.loc_type == __value.loc_type and \
                        self.reg_name == __value.reg_name
            else:
                # ignore reg name for memory locations
                return  self.loc_type == __value.loc_type and \
                        self.offset == __value.offset
        return False

    def __str__(self) -> str:
        if self.loc_type == LocationType.Register:
            return f'{self.reg_name}'
        elif self.loc_type == LocationType.Stack:
            return f'Stack[{self.offset:#x}]'
        else:
            return f'Mem[{self.offset:#x}]'
