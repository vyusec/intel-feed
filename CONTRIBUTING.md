# Contributing

Report findings through the package threat report issue template. Include registry identity, exact versions, artifact hashes, observed behavior, reproduction instructions, references and evidence licenses. Do not upload live malware or secrets to GitHub.

Code and original rules use Apache-2.0. Original intelligence uses CC-BY-4.0; retain third-party attribution. Rule changes require a version bump, benign lookalikes and malicious-pattern regression fixtures, and updated evaluation results. All generated detections still require human review.

Run `make test vet evaluate`. Set `ZOLI_TEST_DATABASE_URL` to a dedicated database to include PostgreSQL integration tests. Synthetic fixtures are inert text and are never executed by CI. Do not introduce workflows that run issue bodies or untrusted contribution code with production credentials.
