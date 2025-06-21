all:
	cd circuits && circom -c main_spend.circom --O0
	cd circuits && circom -c main_proof_of_burn.circom --O0
	python3 main.py > circuits/main_proof_of_burn_cpp/input.json
	cd circuits/main_proof_of_burn_cpp && make -B && ./main_proof_of_burn input.json w