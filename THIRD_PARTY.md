# Third-party material

Dependencies (crates) are listed in `Cargo.lock` with their licenses, checked by
`cargo deny check` (`deny.toml`). This file covers material that is not a dependency but was
derived from other projects.

## gitleaks rule patterns

Several token formats recognized by the `api_key`, `gitlab_token` and `aws_access_key_id` value
types (`src/domain/types/api_key.rs`, `gitlab_token.rs`, `aws.rs`) follow the prefixes, character
sets and lengths of the default rules of gitleaks: Slack, Stripe, OpenAI (the `T3BlbkFJ` marker),
Anthropic, npm, PyPI, Google API keys and OAuth client secrets, SendGrid, Hugging Face,
DigitalOcean, Shopify, HashiCorp Vault, Terraform Cloud, RubyGems, AWS access key ids. lootr
reimplements them as prefix and charset checks (no regexes were copied); the GitLab prefixes come
from GitLab's documentation ("Token prefixes").

    gitleaks - https://github.com/gitleaks/gitleaks
    MIT License

    Copyright (c) 2019 Zachary Rice

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
