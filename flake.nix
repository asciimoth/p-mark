{
  description = "Linux process marking tool";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = {
    self,
    nixpkgs,
    flake-utils,
    pre-commit-hooks,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
      };

      llvm = pkgs.llvmPackages_latest;
      bpfClang = pkgs.writeShellScriptBin "bpf-clang" ''
        exec ${llvm.clang-unwrapped}/bin/clang "$@"
      '';

      checks = {
        pre-commit-check = pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            gotest.enable = true;
            commitizen.enable = true;
            typos.enable = true;
            typos-commit = {
              enable = true;
              description = "Find typos in commit message";
              entry = let script = pkgs.writeShellScript "typos-commit" ''
                typos "$1"
              ''; in builtins.toString script;
              stages = [ "commit-msg" ];
            };
            govet.enable = true;
            gofmt.enable = true;
            golangci-lint.enable = true;
            gotidy = {
              enable = true;
              description = "Makes sure go.mod matches the source code";
              entry = let script = pkgs.writeShellScript "gotidyhook" ''
                go mod tidy -v
              ''; in builtins.toString script;
              stages = [ "pre-commit" ];
            };
          };
        };
      };
    in {
      devShells.default = pkgs.mkShell {
        shellHook = checks.pre-commit-check.shellHook + ''
          export CGO_ENABLED=0

          # For <linux/bpf.h> and <bpf/bpf_helpers.h>
          export CPATH="${pkgs.linuxHeaders}/include:${pkgs.libbpf}/include:$CPATH"

          echo "Using bpf-clang: $(bpf-clang --version | head -n1)"
          echo "Using llvm-strip: $(llvm-strip --version | head -n1)"
        '';

        buildInputs = with pkgs; [
          go
          golangci-lint
          gopls

          typos
          commitizen

          just

          bpfClang
          llvm.llvm

          linuxHeaders # linux/bpf.h
          libbpf # bpf/bpf_helpers.h

          # debug/trace
          bpftools
          pwru
        ];
      };
    });
}
