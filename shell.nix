{ pkgs ? import <nixpkgs> {} }:

let
  python-with-packages = pkgs.python3.withPackages (ps: with ps; [ pip virtualenv ]);
in

pkgs.mkShell {
  buildInputs = [
    pkgs.gcc
    pkgs.nlohmann_json
    pkgs.gmp
    pkgs.rustc
    pkgs.circom
    pkgs.gnumake
    pkgs.foundry
    pkgs.nasm
    python-with-packages
  ];

  shellHook = ''
    if [ ! -d ".venv" ]; then
      echo "Creating Python virtual environment..."
      python -m venv .venv
    fi
    source .venv/bin/activate
    if [ -f requirements.txt ]; then
      echo "Installing Python dependencies..."
      pip install -r requirements.txt
    fi
  '';
}

