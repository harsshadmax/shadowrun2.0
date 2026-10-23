#!/usr/bin/env bash
# One hash over every tracked file that can change behaviour (code, tests, policies, scripts, templates, workflows,
# packaging) but NOT over documentation (*.md) or generated evidence (evidence/, eval/results/). Anyone can run it on a
# checkout and compare with the value recorded in evidence/validation.log: equal means the tested source is exactly the
# submitted source.
cd "$(dirname "$0")/.."
git ls-files -z -- . ':(exclude)evidence' ':(exclude)eval/results' ':(exclude)*.md' | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1
