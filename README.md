# cd thoughts blog 

Jekyll sources for the blog hosted on the Github Pages. A GitHub Action takes care of building the repo and deploying it from `main`.

## Installation

A `devcontainer` is available to launch a dev environement with Jekyll and all its dependencies installed. Refer to the doc of [your favourite editor](https://containers.dev/supporting) to know how to launch it.
By default the container simply starts, it won't automatically begin building or serving the files.

## Build

Use `make build` to generate a development build.

## Serve

Similarly, the blog can be served locally for development purpose (and will reload when changes are made) with `make serve`. This also rebuilds the blog.

You can then access the blog at `localhost:4000`.