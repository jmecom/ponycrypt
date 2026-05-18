{
  description = "Pony language development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.ponyc;
          ponyc = pkgs.ponyc;
          corral = pkgs.pony-corral;
          ponycrypt = pkgs.stdenv.mkDerivation {
            pname = "ponycrypt";
            version = "0.1.0";
            src = ./.;

            nativeBuildInputs = [ pkgs.ponyc ];

            buildPhase = ''
              runHook preBuild
              ponyc ponycrypt -o build
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              install -Dm755 build/ponycrypt $out/bin/ponycrypt
              runHook postInstall
            '';
          };
        });

      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          ponycrypt-tests = pkgs.stdenv.mkDerivation {
            pname = "ponycrypt-tests";
            version = "0.1.0";
            src = ./.;

            nativeBuildInputs = [ pkgs.ponyc ];

            buildPhase = ''
              runHook preBuild
              ponyc ponycrypt_test -p . -o build
              runHook postBuild
            '';

            doCheck = true;

            checkPhase = ''
              runHook preCheck
              ./build/ponycrypt_test
              runHook postCheck
            '';

            installPhase = ''
              runHook preInstall
              mkdir -p $out
              touch $out/passed
              runHook postInstall
            '';
          };
        });

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              ponyc
              pony-corral
              openssl
              (python3.withPackages (python-pkgs: [
                python-pkgs.cryptography
              ]))
            ];

            shellHook = ''
              echo "Pony $(ponyc --version | head -n 1)"
            '';
          };
        });
    };
}
