# Model catalog

## Entity levels

YARA distinguishes:

1. **Family:** named upstream model line and architecture.
2. **Variant:** parameter size, task tuning and upstream revision.
3. **Artifact:** exact files, format, precision/quantization, digest and source.
4. **Serving configuration:** artifact plus runtime, hardware and settings.
5. **Observation:** benchmark or validation result for a serving configuration.

Conflating these levels produces misleading memory and performance claims.

## Required metadata

The executable v0.2 subset captures family, architecture, parameter count, context window, quantization, immutable revision, verified weight shards, license, coarse memory inputs, capabilities and preference. Tokenizer/template hashes, benchmark observations and a context-sensitive KV-cache methodology remain required before production promotion.

- family, variant and immutable upstream revision;
- supported tasks and interface features;
- architecture, parameters and context constraints;
- tokenizer and prompt/template compatibility;
- artifact format, precision, quantization and digest;
- artifact source, size and redistribution status;
- license, use restrictions and attribution requirements;
- compatible runtimes through evidence-backed assertions;
- memory-estimation inputs and methodology;
- quality and performance observations with environments;
- language, modality and safety limitations;
- lifecycle status and review ownership.

## Resource estimation

Static weight size is only the baseline. An estimate considers:

- loaded weights and quantization metadata;
- runtime/kernel overhead;
- key/value cache by layers, precision, context and concurrency;
- temporary workspace and graph capture;
- tensor/pipeline parallelism overhead;
- CPU memory and storage/offload;
- required safety headroom.

The catalog stores parameters and evidence; estimator code computes scenario-specific ranges. A single `vramRequired` number is not sufficient.

## Quality evidence

Quality is task- and evaluation-specific. Records include benchmark version, prompt/evaluation configuration, score, variance when available and applicability. YARA should prefer several relevant observations over one aggregate leaderboard number and must expose when the requested language/domain lacks evidence.

## Licensing and artifacts

Model availability, permission to use and permission to redistribute are distinct. Air-gapped bundle creation is allowed only when the artifact license and policy permit it. Otherwise YARA may produce an acquisition manifest for the operator without redistributing weights.

## Compatibility

A model is selectable only as part of a serving candidate with a positive runtime/artifact/hardware assertion. Architecture support in runtime documentation is weaker evidence than an automated load-and-inference test for the exact variant.

Accordingly, the two Qwen AWQ snapshots in v0.2 are `experimental`: their identities and weight files are verified, while their runtime/hardware tuples still await YARA-owned contract tests.

## Safety and suitability

The catalog may describe known intended use, limitations and safety evaluation evidence, but YARA does not certify a model as safe for an organization's application. Regulated or high-impact use requires domain-specific review outside the generic planner.
