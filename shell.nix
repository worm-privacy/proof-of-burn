{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.gcc              # The compiler
    pkgs.nlohmann_json    # The header-only json.hpp
    pkgs.gmp              # The GMP library (headers + libgmp)
    pkgs.rustc
    pkgs.circom
    pkgs.gnumake
    pkgs.gcc
    pkgs.foundry
    pkgs.nasm
    pkgs.python3
  ];
}
