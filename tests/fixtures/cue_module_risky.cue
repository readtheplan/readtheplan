module: "example.com/platform"
language: version: "v0.17.0"
source: {
    kind: "git"
    repo: "https://github.com/example/platform"
}
deps: {
    "example.com/stable/module@v1": {
        v: "v1.2.3"
        default: true
    }
    "example.com/floating/module@v0": {
        v: "main"
    }
}
