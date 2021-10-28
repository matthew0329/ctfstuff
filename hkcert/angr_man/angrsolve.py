import angr
import claripy

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
