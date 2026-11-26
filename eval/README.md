# eval

How well PhishLens actually works: dataset collection, a frozen test set,
the scripts that run the engine over it, and the results (precision, recall,
false-positive rate per check). Built in the "Evaluation" milestone.

These folders are git-ignored and must stay that way:

- `data/raw/`, `data/cache/`, `data/screenshots/`: collected samples, fetch
  caches and sandbox screenshots. Real phishing samples hold working
  malicious links, and real emails hold other people's personal data.
- `results/runs/`: per-run output.

What is committed: the scripts, the definition of the frozen test set, and
summary results.
