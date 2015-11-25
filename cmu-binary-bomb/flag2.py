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
# I thought this would work, but ended up doing stack_push instead
# rsp = 0x7fffffffdcf0

    state = proj.factory.blank_state(addr=0x400f0a)
# rsp = state.memory.load(state.regs.rsp)

    for i in xrange(1, 6):
        # state.memory.store(rsp + i*4, state.se.BVS('int{}'.format(i), 4*8))
        state.stack_push(state.se.BVS('int{}'.format(i), 4*8))

    path = proj.factory.path(state=state)
    ex = proj.surveyors.Explorer(start=path, find=(0x400f3c,), avoid=(bomb_explode, 0x400f10, 0x400f20,), enable_veritesting=True)
    ex.run()
    if ex.found:
        found = ex.found[0].state

        answer = []

        for x in xrange(3):
            curr_int = found.se.any_int(found.stack_pop())
            # Totally forgot how this should work - 0.0
            answer.append(str(curr_int & 0xffff))
            answer.append(str(curr_int>>32 & 0xffff))

        print("Flag 2:")
        print(' '.join(answer))

def test():
    assert main() == '1 2 4 8 16 32'

if __name__ == '__main__':
    main()
