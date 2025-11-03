all:
	cd circuits && circom -c main_spend.circom --O0 && cd main_spend_cpp && make -B
	cd circuits && circom -c main_proof_of_burn.circom --O0 && cd main_proof_of_burn_cpp && make -B
	python3 -m tests.main
	cd circuits/main_proof_of_burn_cpp && ./main_proof_of_burn input.json witness.wtns
	cd circuits/main_spend_cpp && ./main_spend input.json witness.wtns