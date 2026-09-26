# hello-web

A minimal Attestry skill package, used by the examples in the main README.

It exposes one tool, `fetch_page`, described in `fetch_page.nts.json`. That
description declares `network: true`, which is what `attestry registry show`
surfaces before you install it.

```bash
attestry registry pack examples/skills/hello-web
attestry registry publish examples/skills/hello-web --source ./hello-web-1.0.0.tar.gz
attestry registry install hello-web@^1.0.0
```
