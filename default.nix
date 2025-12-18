{
  python3Packages,
  vte-gtk4,
  gtk4,
  libadwaita,
  rsync,
  sshpass,
  pkg-config,
  libsecret,
  wrapGAppsHook4,
  gobject-introspection,
}:

python3Packages.buildPythonApplication {
  pname = "zashterm";
  version = "0.1.0";

  src = ./.;

  pyproject = true;

  build-system = with python3Packages; [ uv-build ];
  dependencies = with python3Packages; [
    pygobject3
    pycairo
    setproctitle
    requests
    py7zr
  ];

  nativeBuildInputs = [
    pkg-config
    wrapGAppsHook4
    gobject-introspection
  ];
  buildInputs = [
    vte-gtk4
    gtk4
    libadwaita
    rsync
    sshpass
    libsecret
  ];

  postInstall = ''
    cp $src/usr/share $out/share -r
    install -Dm755 $src/usr/bin/zashterm $out/bin/zashterm
    install -Dm755 $src/usr/bin/zash $out/bin/zash
  '';
}
