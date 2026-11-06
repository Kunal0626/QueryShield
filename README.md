# QueryShield

**SQL-injection detection proxy**

> Status: In progress. Code is being built and will be added here.

Sits in front of a database-backed web app and blocks requests that look like SQL injection before they reach it.

## How it works
1. Requests are URL-decoded and normalised so case changes and comment padding do not hide a payload.
2. An Aho-Corasick automaton matches many attack signatures in one linear pass.
3. A small SQL tokenizer catches structure that plain string matching misses.
4. Blocked requests get a 403; clean ones are forwarded unchanged.
5. Evaluated against a deliberately vulnerable MySQL-backed app with a labelled set of attack and normal inputs.

## Stack
- Java
- MySQL
- Aho-Corasick
- JDK HttpServer

## CS concepts
- Aho-Corasick automaton (DSA)
- Tokenizing and parsing
- SQL injection
- Precision vs false positives

## Roadmap
- [ ] Aho-Corasick implementation with unit tests
- [ ] Request normaliser (URL-decode, case, comments)
- [ ] SQL tokenizer rules
- [ ] Reverse proxy built on `HttpServer`
- [ ] Deliberately vulnerable demo app (MySQL)
- [ ] Labelled attack / benign dataset
- [ ] Evaluation: detection rate and false-positive rate, before and after tuning

## Usage
Coming soon.

---
Part of my portfolio: [github.com/Kunal0626](https://github.com/Kunal0626)
