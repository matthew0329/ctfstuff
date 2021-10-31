## Angr Men 

## Resources
'''
Find the input that make the program exit with exit code 0.
'''
'''
Hint: Google "angr"
'''
'''
angr_man (binary file)
'''

## Write-up
we knew we need to google angr but first, lets take a look of our binary file
![image](https://user-images.githubusercontent.com/49106442/139585822-530a5f50-def3-414e-97e9-b7d8e06f0110.png)

invalid size huh?
Lets use ghidra to disassemble it

![Screenshot_2021-10-31_09-41-31](https://user-images.githubusercontent.com/49106442/139586645-928ec115-aca0-46c4-9548-4060aa13edce.png)

found this function which prints what we see in the program
we can see that theres a if statement depending on the value of cVar1
we probably want to get the segment where it prints out 'It is the music of.....'

the program was too complicated to be understanded for me, but this question itself tell us that we can solve it with angr
so i started to google what angr is, and what it can do to solve this challenge

Angr will do symbolic execution to find out what input could lead to the specific segment of code to execute, according to google
what we need to do is just to provide it the input size, type, and base address

![Screenshot_2021-10-31_09-55-33](https://user-images.githubusercontent.com/49106442/139588815-6d737366-5d29-43b6-8704-d3ac564d65f2.png)
  this is what i found about the input size, it should be 0x21 = 33 in length
![Screenshot_2021-10-31_10-40-55](https://user-images.githubusercontent.com/49106442/139588884-0feba32d-c1df-4239-9632-718eaed383ee.png)
  And we could see that our input is probably being verified and should be printable ascii code

We also need to find out the address that we want to reach('It is the...') and the address we want to advoid('bye')

And just use angr to write a python script, no, actually i literally find a sample script that we can use on their documentation LOL
We just need to specify all possible input and what output we want to find


## template that i found
I literally just copy from their sample and changed only at those statements that i bolded siu444
It tooks about 37seconds to run and get this easy flag
```python
#!/usr/bin/env python
#coding: utf-8
import angr
import claripy
import time

#compiled on ubuntu 18.04 system:
#https://github.com/b01lers/b01lers-ctf-2020/tree/master/rev/100_little_engine

def main():
    #setup of addresses used in program
    #addresses assume base address of
    base_addr = 0x100000

    #length of desired input is 75 as found from reversing the binary in ghidra
    #need to add 4 times this size, since the actual array is 4 times the size
    #1 extra byte for first input
    input_len = **32**

    #seting up the angr project
    p = angr.Project('**./angr_man**', main_opts={'base_addr': base_addr})

    #looking at the code/binary, we can tell the input string is expected to fill 22 bytes,
    # thus the 8 byte symbolic size. Hopefully we can find the constraints the binary
    # expects during symbolic execution
    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]

    #extra \n for first input, then find the flag!
    flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')])

    # enable unicorn engine for fast efficient solving
    st = p.factory.full_init_state(
            args=['**./angr_man**'],
            add_options=angr.options.unicorn,
            stdin=flag
           )

    #constrain to non-newline bytes
    #constrain to ascii-only characters
    for k in flag_chars:
        st.solver.add(k < 0x7f)
        st.solver.add(k > 0x20)

    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    sm = p.factory.simulation_manager(st)
    sm.run()

    #grab all finished states, that have the win function output in stdout
    y = []
    for x in sm.deadended:
        if b"**It is the **" in x.posix.dumps(1):
            y.append(x)

    #grab the first output
    **print(y[0].posix.dumps(0))**
 
if __name__ == "__main__":
    before = time.time()
    **main()**
    after = time.time()
    print("Time elapsed: {}".format(after - before))
```
 
## Another script

  I actually dont know this template exisited when i attempt this question and wrote the following scripts that uses the address of the two print statement and let angr find which input could reach that address

```python
import angr
import claripy
import time

before = time.time()

flag_length = 32

base_address = 0x00100000
success_addr = 0x0010169b
failure_addr = 0x001016ca


project = angr.Project("./angr_man", main_opts = {"base_addr" : base_address})
#create vector
flag_chars = [claripy.BVS(f"flag_char{i}", 8) for i in range(flag_length)]
flag = claripy.Concat(*flag_chars +  [claripy.BVV(b'\n')])

state = project.factory.full_init_state(
		args=["./angr_man"],
		add_options = angr.options.unicorn,
		stdin=flag
	)

simgr = project.factory.simulation_manager(state)
simgr.explore(find=success_addr, avoid=failure_addr)

if len(simgr.found) > 0:
	for found in simgr.found:
		print(found.posix.dumps(0))

after = time.time()
print("Time elapsed: {}".format(after - before))
```


