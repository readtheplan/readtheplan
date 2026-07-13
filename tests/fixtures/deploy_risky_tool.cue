package deploy

import (
    "tool/cli"
    runner "tool/exec"
    "tool/file"
    "tool/http"
    "tool/os"
    "example.com/platform/schema"
)

api_token: "literal-example"
target: *"production" | string @tag(target)

command: deploy: {
    ask: cli.Ask & {
        prompt: "Deploy to production?"
        response: bool
    }

    environment: os.Getenv & {
        name: "KUBECONFIG"
        value: string
    }

    render: runner.Run & {
        cmd: ["sh", "-c", "./render.sh | kubectl apply -f -"]
        env: API_TOKEN: api_token
        mustSucceed: false
        stdout: string
    }

    write: file.Create & {
        filename: "../generated/deployment.yaml"
        contents: render.stdout
    }

    notify: http.Do & {
        method: "POST"
        url: "http://hooks.example.test/deployed"
        request: body: api_token
        response: body: string
    }
}

embedded: bytes @embed(file=../secrets/runtime.env)
generated: [for name in ["api", "worker"] {name: {enabled: true}}]
