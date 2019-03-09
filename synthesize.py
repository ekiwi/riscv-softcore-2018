#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# synthesize a core


import sys, os, pathlib, re, shutil, subprocess, re



lattice_dir_re = re.compile(r'iCEcube2\.(\d\d\d\d)\.(\d\d)')
def parse_lattice_dir(install_dir):
	m = lattice_dir_re.match(os.path.basename(install_dir))
	if m is None: return None
	return int(m.group(1)), int(m.group(2))
def find_lattice(install_dir=None):
	if install_dir is None:
		install_dir = os.path.expanduser(os.path.join('~', 'lscc'))
	# check if specific version specified
	if parse_lattice_dir(install_dir) is None:
		# try to find most recent version
		versions = [(*parse_lattice_dir(dd), dd) for dd in os.listdir(install_dir) if parse_lattice_dir(dd) is not None]
		if len(versions) == 0: return None
		install_dir = os.path.join(install_dir, list(sorted(versions))[-1][-1])
	return install_dir

#def create_lattice_project(lattice_dir, project_dir, sources, pins):


def require_prog(name):
	ret = subprocess.run(['which', name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	assert ret.returncode == 0, f"Program {name} not found in path!\n{ret}"

def parse_ints_from_report(report, metrics, tool=''):
	dd = dict()
	for needle, name in metrics:
		m = re.search(needle + r'\s+(\d+)', report)
		assert m is not None, f"Failed to find {name} ({needle}) in {tool} output!"
		dd[name] = int(m.group(1))
	return dd

def parse_yosys(report):
	cells = ['carry', 'dff', 'dffe', 'dffer', 'dffes', 'dffr', 'dffs', 'dffsr', 'dffss', 'lut4', 'spram256ka']
	metrics = [
		('Number of wires:', 'wires'),
		('Number of cells:', 'cells'),
		*[(f'SB_{cc.upper()}', cc) for cc in cells]
	]
	return parse_ints_from_report(report, metrics, 'yosys')

def parse_arachne(report):
	cells = ['BRAMs', 'DFF', 'CARRY', 'DFF PASS', 'CARRY PASS', 'PLLs', 'MAC16s', 'SPRAM256KAs']
	metrics = [
		('IOs', 'io'),
		('GBs', 'global_buffer'),
		('LCs', 'logic_cells'),
		*[(cc, cc.lower().replace(' ', '_')) for cc in cells]
	]
	return parse_ints_from_report(report, metrics, 'arachne')

def parse_icetime(report):
	logic_lvl = re.search(r'Total number of logic levels:\s+(\d+)', report)
	assert logic_lvl is not None, "Failed to find logic levels in icetime report"
	path_delay = re.search(r'Total path delay: (\d+\.\d+) ns \((\d+\.\d+) MHz\)', report)
	assert path_delay is not None, "Failed to find path delay in icetime report"
	return {
		'logic_levels': int(logic_lvl.group(1)),
		'path_delay': float(path_delay.group(1)),
		'freq_max': float(path_delay.group(2))
	}


def make_icestorm(device, project, build_dir):
	assert os.path.isdir(build_dir), f"{build_dir} is not a directory/does not exist"
	require_prog('yosys')
	require_prog('arachne-pnr')
	require_prog('icetime')
	# files
	blif = os.path.join(build_dir, project['name'] + '.blif')
	asc = os.path.join(build_dir, project['name'] + '.asc')
	rpt = os.path.join(build_dir, project['name'] + '.rpt')

	# synthesis
	srcs = [os.path.join(project['dir'], ff) for ff in project['src']]
	cmd = ['yosys', '-p', f"synth_ice40 -top {project['top']} -blif {blif}"] + srcs
	ret = subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
	syn_report = parse_yosys(ret.stdout.decode('utf-8'))

	# place and route
	io_constraints = os.path.join(project['dir'], project['io'])
	cmd = ['arachne-pnr', '-d', device['arachne'], '-P', device['package'], '-o', asc, '-p', io_constraints, blif]
	ret = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	pnr_report = parse_arachne(ret.stderr.decode('utf-8'))

	# static timing analysis
	cmd = ['icetime', '-d', device['icetime'], '-mtr', rpt, asc]
	subprocess.run(cmd, check=True, stdout=subprocess.PIPE)

	# read timing report
	with open(rpt) as ff:
		timing = ff.read()
	timing_report =  parse_icetime(timing)
	return {'syn': syn_report, 'pnr': pnr_report, 'timing': timing_report}


def main():
	# TODO: remove hard coded path
	repo_path = os.path.expanduser(os.path.join('~', 'riscv-softcore', 'riscv-softcore-2018'))
	enginev_path = os.path.expanduser(os.path.join('~', 'riscv-softcore', 'engine-V'))
	# os.environ["PATH"] += os.pathsep + os.path.expanduser(os.path.join('~', 'd', 'yosys-ucb'))
	# print(os.environ["PATH"].split(':'))

	#print(find_lattice())

	device = {
		'name': 'iCE40UP5K',
		'arachne': '5k',
		'icetime': 'up5k',
		'package': 'uwg30'
	}

	# mf8 project description
	mf8_project = {
		'dir': os.path.join(repo_path, 'engine-v'),
		'name': 'engine-v',
		'top': 'MF8A18_SoC',
		'src': [os.path.join('hdl', ff) for ff in [
			'RAM32K.v', 'ROM1K16.v',
			'addsub8.v',
			'mf8_alu.v', 'mf8_pcs.v', 'mf8_reg.v', 'mf8_core.v',
			'MF8A18_SoC.v', 'MF8A18.v',
		]],
		'io': 'syn/io.pcf',
		'clock': 'syn/clk.sdc'
	}

	mf8_orig_project = {
		'dir': os.path.join(enginev_path, 'boards', 'lattice', 'iCE40-UltraPlus-MDP', 'icecube2'),
		'name': 'engine-v-orig',
		'top': 'MF8A18_SoC',
		'src': [os.path.join('src', ff) for ff in [
			'addsub8.v', 'RAM32K.v',
			'mf8_alu.v', 'mf8_pcs.v', 'mf8_reg.v', 'mf8_core.v',
			'MF8A18_SoC.v', 'MF8A18.v', 'ROM512K16.v'
		]],
		'io': 'src/io.pcf',
		'clock': 'src/clk.sdc'
	}

	use_prj = mf8_project

	build_dir = os.path.join(use_prj['dir'], 'build')
	if not os.path.isdir(build_dir):
		os.mkdir(build_dir)
	report = make_icestorm(device, use_prj, build_dir)
	print(f"Synthesis:")
	print(f"\tLUTs:    {report['syn']['lut4']}")
	print(f"\tCarries: {report['syn']['carry']}")
	dffs = sum(val for key, val in report['syn'].items() if key.startswith('dff'))
	print(f"\tDFFs:    {dffs}")
	print(f"\tSRAMs:   {report['syn']['spram256ka']}")
	print(f"Place & Route:")
	print(f"\tLCs:   {report['pnr']['logic_cells']}")
	print(f"\tBRAMs: {report['pnr']['brams']}")
	print(f"\tSRAMs: {report['pnr']['spram256kas']}")
	print(f"Timing:")
	print(f"\tLogic Levels:  {report['timing']['logic_levels']}")
	print(f"\tCritical Path: {report['timing']['path_delay']} ns")
	print(f"\tf_max:         {report['timing']['freq_max']} MHz")

	return 0


if __name__ == '__main__':
	sys.exit(main())