all:
	circom -c proof_of_burn.circom --O0
	python3 main.py > proof_of_burn_cpp/input.json
	cd proof_of_burn_cpp && make -B && ./proof_of_burn input.json w