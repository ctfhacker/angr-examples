## Binary found here: http://csapp.cs.cmu.edu/3e/bomb.tar

import angr, logging
from subprocess import Popen, PIPE
from itertools import product
import struct

def main():
    proj = angr.Project('bomb', load_options={'auto_load_libs':False})

    logging.basicConfig()
    logging.getLogger('angr.surveyors.explorer').setLevel(logging.DEBUG)

    def nop(state):
        return

    bomb_explode = 0x40143a

    # Start analysis at the phase_3 function after the sscanf
    state = proj.factory.blank_state(addr=0x400f60)

    """
    After the scanf of "%d %d" the stack looks like this after input of '1 2':
    +0000 0x7fffffffdcf0  00 00 00 00  00 00 00 00  01 00 00 00  02 00 00 00

    To emulate this, we can push 4 - 32 bit symbolic variables on the stack.
    We don't actually care about the first 2.
    """

    for i in xrange(4):
        state.stack_push(state.se.BVS('int{}'.format(i), 4*8))

    # Attempt to find a path to the end of the phase_3 function while avoiding the bomb_explode
    path = proj.factory.path(state=state)
    ex = proj.surveyors.Explorer(start=path, find=(0x400fc9,),
                                 avoid=(bomb_explode,),
                                 enable_veritesting=True)
    ex.run()
    if ex.found:
        found = ex.found[0].state
        found.stack_pop()

        # Note, this will only find the first possible solution.
        # There are 6 possible solutions
        answer = []

        curr_int = found.se.any_int(found.stack_pop())
        answer.append(str(curr_int & 0xffff))
        answer.append(str(curr_int>>32 & 0xffff))
        return ' '.join(answer)

def test():
    assert main() == '0 207'

if __name__ == '__main__':
    print main()
