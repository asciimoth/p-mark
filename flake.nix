# Usage:
# - Build the package: nix build .#pmark
# - Run from the flake: nix run .#pmark -- -watcher -pin-path /sys/fs/bpf/pmark
# - Add to tmp shell: nix shell .#pmark
# - Add to profile: nix profile add .#pmark
# - Install the package in a NixOS config:
#     environment.systemPackages = [ inputs.p-mark.packages.${pkgs.system}.pmark ];
# - Enable the NixOS daemon service from this flake:
#     imports = [ inputs.p-mark.nixosModules.pmark ];
#     services.pmark = {
#       enable = true;
#       fwmark = true;
#       fmarkValue = "0xeb9f0001";
#       rules.comm = [ "firefox" "chromium" ];
#     };
#   The service runs pmark as root because loading/attaching eBPF programs and
#   setting SO_MARK normally require root or equivalent capabilities.
{
  description = "Linux process marking tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

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
      lib = pkgs.lib;

      version = self.shortRev or self.dirtyShortRev or "dev";

      llvm = pkgs.llvmPackages_latest;
      bpfClang = pkgs.writeShellScriptBin "bpf-clang" ''
        exec ${llvm.clang-unwrapped}/bin/clang "$@"
      '';

      pmark = pkgs.buildGoModule {
        pname = "pmark";
        inherit version;
        src = ./.;

        vendorHash = "sha256-fe4XLsIwdSMSae8MMU52Y3+ZJMTyR9r+cZY781GqdLk=";
        proxyVendor = true;

        nativeBuildInputs = [
          bpfClang
          llvm.llvm
        ];

        buildInputs = [
          pkgs.linuxHeaders
          pkgs.libbpf
        ];

        env.CGO_ENABLED = "0";

        preBuild = ''
          export CPATH="${pkgs.linuxHeaders}/include:${pkgs.libbpf}/include:$CPATH"
          go generate ./...
        '';

        subPackages = [ "cmd" ];

        postInstall = ''
          if [ -e "$out/bin/cmd" ] && [ ! -e "$out/bin/pmark" ]; then
            mv "$out/bin/cmd" "$out/bin/pmark"
          fi

          if [ ! -x "$out/bin/pmark" ]; then
            echo "expected ./cmd to build an executable pmark binary" >&2
            exit 1
          fi
        '';

        doCheck = false;

        meta = with lib; {
          description = "Linux process lifetime marking daemon with optional fwmark integration";
          homepage = "https://github.com/asciimoth/p-mark";
          license = licenses.mit;
          mainProgram = "pmark";
          platforms = platforms.linux;
        };
      };

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
              entry = let
                script = pkgs.writeShellScript "typos-commit" ''
                  typos "$1"
                '';
              in
                builtins.toString script;
              stages = [ "commit-msg" ];
            };
            govet.enable = true;
            gofmt.enable = true;
            golangci-lint.enable = true;
            gotidy = {
              enable = true;
              description = "Makes sure go.mod matches the source code";
              entry = let
                script = pkgs.writeShellScript "gotidyhook" ''
                  go mod tidy -v
                '';
              in
                builtins.toString script;
              stages = [ "pre-commit" ];
            };
          };
        };
      };
    in {
      packages = {
        inherit pmark;
        default = pmark;
      };

      apps = {
        pmark = flake-utils.lib.mkApp {
          drv = pmark;
          exePath = "/bin/pmark";
        };
        default = flake-utils.lib.mkApp {
          drv = pmark;
          exePath = "/bin/pmark";
        };
      };

      inherit checks;

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

          goreleaser
        ];
      };
    })
    // {
      nixosModules.pmark = {
        config,
        lib,
        pkgs,
        ...
      }: let
        cfg = config.services.pmark;

        mkArg = flag: value:
          lib.optionals (value != null) [ flag (toString value) ];

        mkCommaArg = flag: values:
          lib.optionals (values != null) [ flag (lib.concatStringsSep "," values) ];

        args =
          [ "${lib.getExe cfg.package}" ]
          ++ mkArg "-pin-path" cfg.pinPath
          ++ mkArg "-http-addr" cfg.httpAddr
          ++ lib.optionals cfg.fwmark [ "-fwmark" ]
          ++ mkArg "-fmark-value" cfg.fmarkValue
          ++ mkArg "-mark-value" cfg.markValue
          ++ mkArg "-mark-priority" cfg.markPriority
          ++ mkCommaArg "-rule-comm" cfg.rules.comm
          ++ mkCommaArg "-rule-cmd" cfg.rules.cmd
          ++ mkCommaArg "-rule-exe" cfg.rules.exe
          ++ mkCommaArg "-rule-ppid" cfg.rules.ppid
          ++ cfg.extraArgs;
      in {
        options.services.pmark = {
          enable = lib.mkEnableOption "p-mark process marking daemon";

          package = lib.mkOption {
            type = lib.types.package;
            default = self.packages.${pkgs.stdenv.hostPlatform.system}.pmark;
            defaultText = lib.literalExpression "inputs.p-mark.packages.\${pkgs.stdenv.hostPlatform.system}.pmark";
            description = "Package providing the pmark daemon.";
          };

          pinPath = lib.mkOption {
            type = lib.types.str;
            default = "/sys/fs/bpf/pmark";
            example = "/sys/fs/bpf/pmark";
            description = "bpffs directory for pinned p-mark maps.";
          };

          httpAddr = lib.mkOption {
            type = lib.types.str;
            default = "127.0.0.1:8050";
            example = "127.0.0.1:8050";
            description = "HTTP control/admin panel listen address passed as -http-addr.";
          };

          fwmark = lib.mkEnableOption "Linux fwmark socket marking integration";

          fmarkValue = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            example = "0xeb9f0001";
            description = ''
              Linux fwmark-format value passed as -fmark-value. pmark derives
              the full 64-bit process mark from this value.
            '';
          };

          markValue = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            example = "16978289124505026561";
            description = ''
              Explicit 64-bit mark value passed as -mark-value.
            '';
          };

          markPriority = lib.mkOption {
            type = lib.types.nullOr lib.types.int;
            default = null;
            example = 10;
            description = "Signed int8 priority passed as -mark-priority; higher priority wins.";
          };

          rules = {
            comm = lib.mkOption {
              type = lib.types.nullOr (lib.types.listOf lib.types.str);
              default = null;
              example = [ "firefox" "chromium" ];
              description = ''
                Regexps matched against process comm and passed as a
                comma-separated -rule-comm value.  null leaves the binary
                default unchanged.
              '';
            };

            cmd = lib.mkOption {
              type = lib.types.nullOr (lib.types.listOf lib.types.str);
              default = null;
              example = [ "profile-name" ];
              description = ''
                Regexps matched against process cmdline and passed as a
                comma-separated -rule-cmd value.
              '';
            };

            exe = lib.mkOption {
              type = lib.types.nullOr (lib.types.listOf lib.types.str);
              default = null;
              example = [ "/usr/bin/firefox" "firefox" ];
              description = ''
                Regexps matched against process executable path and basename,
                passed as a comma-separated -rule-exe value.
              '';
            };

            ppid = lib.mkOption {
              type = lib.types.nullOr (lib.types.listOf lib.types.str);
              default = null;
              example = [ "1234" ];
              description = ''
                Parent process id matchers passed as a comma-separated
                -rule-ppid value.
              '';
            };
          };

          extraArgs = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
            example = [ "-watch-interval" "500ms" ];
            description = "Extra command line arguments passed to pmark.";
          };
        };

        config = lib.mkIf cfg.enable {
          assertions = [
            {
              assertion = !(cfg.fmarkValue != null && cfg.markValue != null);
              message = "services.pmark.fmarkValue and services.pmark.markValue are mutually exclusive.";
            }
          ];

          warnings =
            lib.optional (cfg.fmarkValue != null && !cfg.fwmark) ''
              services.pmark.fmarkValue is set but services.pmark.fwmark is false.
              The process mark will be derived from the fwmark value, but pmark
              will not install fwmark socket-marking eBPF hooks.
            '';

          environment.systemPackages = [ cfg.package ];

          systemd.services.pmark = {
            description = "p-mark process marking daemon";
            documentation = [ "https://github.com/asciimoth/p-mark" ];
            wantedBy = [ "multi-user.target" ];
            after = [ "network.target" ];
            serviceConfig = {
              Type = "simple";
              ExecStartPre = lib.escapeShellArgs [
                "${pkgs.coreutils}/bin/mkdir"
                "-p"
                cfg.pinPath
              ];
              ExecStart = lib.escapeShellArgs args;
              Restart = "on-failure";
              RestartSec = "5s";
            };
          };
        };
      };

      nixosModules.default = self.nixosModules.pmark;
    };
}
