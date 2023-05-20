{
  description = "concealed";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
  };

  outputs = { self, nixpkgs }:
  let
    pname = "concealed";
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ self.overlay ];
    };
  in {
    packages.${system}.${pname} = pkgs.${pname};
    defaultPackage.${system} = pkgs.${pname};

    overlay = final: prev: {
      "${pname}" = (import ./Cargo.nix {
        pkgs = final;
      }).rootCrate.build;
    };

    devShell.${system} = with pkgs; mkShell {
      buildInputs = [
        bind
        cargo
        crate2nix
        openssl.dev
        pkgconfig
        rustc
        rustfmt
      ];
    };
  };
}
