all:
	cd circuits && circom -c main_spend.circom --O0
	cd circuits && circom -c main_proof_of_burn.circom --O0 && cd main_proof_of_burn_cpp && make -B
	python3 main.py > circuits/main_proof_of_burn_cpp/input.json
	cd circuits/main_proof_of_burn_cpp && ./main_proof_of_burn input.json witness.wtns